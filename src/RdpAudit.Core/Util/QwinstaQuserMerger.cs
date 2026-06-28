// File:    src/RdpAudit.Core/Util/QwinstaQuserMerger.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure helper that augments parsed qwinsta rows with information from quser. Some
//          Windows builds emit a qwinsta row with a blank SESSIONNAME column for a
//          disconnected user (the row still carries username, ID and STATE). The same user
//          shows up in quser with the same ID and STATE but quser reports its own
//          SESSIONNAME column even when qwinsta left it blank — so quser can repair the
//          row. The merger never invents data: it only fills the SessionName when both the
//          ID and STATE match an entry returned by quser, and only when the qwinsta row's
//          existing SessionName is blank. This is intentionally conservative — quser rows
//          for sessions not present in qwinsta are NOT injected to avoid double-counting.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Outcome of <see cref="QwinstaQuserMerger.Merge"/>.</summary>
public sealed record QwinstaQuserMergeResult(int RowsAugmented)
{
	/// <summary>True when at least one qwinsta row had its blank SessionName filled from quser.</summary>
	public bool AnyApplied => RowsAugmented > 0;
}

/// <summary>Pure helper that uses quser rows to fill blank SessionName values in qwinsta rows.</summary>
public static class QwinstaQuserMerger
{
	/// <summary>Augments <paramref name="qwinstaRows"/> in place: every entry whose SessionName
	/// is blank, when there is exactly one quser row matching by (SessionId, normalized State),
	/// is replaced with a new row that carries quser's SessionName. The username on the qwinsta
	/// row is preserved (qwinsta is authoritative for which user owns the WTS session id).
	/// Returns the number of rows that were augmented.</summary>
	public static QwinstaQuserMergeResult Merge(
		IList<QwinstaSessionRow> qwinstaRows,
		IReadOnlyList<QuserSessionRow> quserRows)
	{
		ArgumentNullException.ThrowIfNull(qwinstaRows);
		ArgumentNullException.ThrowIfNull(quserRows);

		int augmented = 0;
		for (int i = 0; i < qwinstaRows.Count; i++)
		{
			QwinstaSessionRow row = qwinstaRows[i];
			if (!string.IsNullOrWhiteSpace(row.SessionName))
			{
				continue;
			}

			string qwinstaState = QwinstaParser.NormalizeState(row.State);
			QuserSessionRow? match = FindUniqueMatch(quserRows, row.SessionId, qwinstaState);
			if (match is null)
			{
				continue;
			}

			if (string.IsNullOrWhiteSpace(match.SessionName))
			{
				continue;
			}

			qwinstaRows[i] = row with { SessionName = match.SessionName.Trim() };
			augmented++;
		}

		return new QwinstaQuserMergeResult(augmented);
	}

	/// <summary>Finds the single quser row that matches the given (SessionId, NormalizedState).
	/// Returns null when no row matches or when more than one matches (ambiguity).</summary>
	private static QuserSessionRow? FindUniqueMatch(
		IReadOnlyList<QuserSessionRow> quserRows,
		int sessionId,
		string qwinstaNormalizedState)
	{
		QuserSessionRow? found = null;
		foreach (QuserSessionRow q in quserRows)
		{
			if (q.SessionId != sessionId)
			{
				continue;
			}

			string normalized = QwinstaParser.NormalizeState(q.State);
			if (!string.Equals(normalized, qwinstaNormalizedState, StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			if (found is not null)
			{
				return null;
			}

			found = q;
		}

		return found;
	}
}
