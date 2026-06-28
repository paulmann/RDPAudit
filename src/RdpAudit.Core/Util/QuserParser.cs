// File:    src/RdpAudit.Core/Util/QuserParser.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure parser for the textual output of "quser" (a.k.a. "query user") used as a
//          secondary source for live RDP session enrichment when qwinsta produces rows with
//          a blank SESSIONNAME column (Windows occasionally emits disconnected user rows that
//          way). Header-aware: when an English header line is present the column offsets are
//          used directly so a blank SessionName column is still attributed correctly; the
//          parser also tolerates the leading ">" "current session" marker and trailing
//          IDLE TIME / LOGON TIME columns. Robust against missing columns; lines that cannot
//          be parsed are dropped without throwing. The parser does not invent state values
//          and never converts strings: NormalizeState() in QwinstaParser handles state
//          canonicalisation so qwinsta and quser rows compare apples-to-apples.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>One row parsed from <c>quser</c> output. Note that <c>quser</c> only reports
/// sessions that have a real user attached — listener / services / console rows that the
/// qwinsta tool emits are not produced by <c>quser</c>, which is exactly what makes it useful
/// for repairing blank-SessionName rows in qwinsta output.</summary>
public sealed record QuserSessionRow(
	string UserName,
	string SessionName,
	int SessionId,
	string State,
	bool IsCurrent);

/// <summary>Pure parser for the textual output of <c>quser</c> / <c>query user</c>.</summary>
public static class QuserParser
{
	private const string HeaderUserName = "USERNAME";
	private const string HeaderSessionName = "SESSIONNAME";
	private const string HeaderId = "ID";
	private const string HeaderState = "STATE";
	private const string HeaderIdleTime = "IDLE";

	/// <summary>Parses the stdout output of <c>quser</c>. Returns an empty list when no usable
	/// rows are present. Lines that cannot be parsed are silently dropped — the parser never
	/// throws on operator input.</summary>
	public static IReadOnlyList<QuserSessionRow> Parse(string? stdOut)
	{
		List<QuserSessionRow> rows = new();
		if (string.IsNullOrWhiteSpace(stdOut))
		{
			return rows;
		}

		string[] lines = stdOut.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
		QuserColumnLayout? layout = LocateEnglishHeader(lines);

		foreach (string raw in lines)
		{
			string line = raw.TrimEnd();
			if (line.Length == 0)
			{
				continue;
			}

			QuserSessionRow? row = layout is not null
				? TryParseWithLayout(line, layout)
				: TryParseHeuristic(line);
			if (row is not null)
			{
				rows.Add(row);
			}
		}

		return rows;
	}

	private static QuserColumnLayout? LocateEnglishHeader(IReadOnlyList<string> lines)
	{
		foreach (string raw in lines)
		{
			string line = raw.TrimEnd();
			if (line.Length == 0)
			{
				continue;
			}

			string upper = line.ToUpperInvariant();
			int userNameCol = IndexOfWord(upper, HeaderUserName);
			int sessionNameCol = IndexOfWord(upper, HeaderSessionName);
			int idCol = IndexOfWord(upper, HeaderId);
			int stateCol = IndexOfWord(upper, HeaderState);
			int idleCol = IndexOfWord(upper, HeaderIdleTime);
			if (userNameCol < 0 || idCol < 0 || stateCol < 0)
			{
				continue;
			}

			return new QuserColumnLayout(
				UserNameStart: userNameCol,
				SessionNameStart: sessionNameCol,
				IdStart: idCol,
				StateStart: stateCol,
				IdleStart: idleCol);
		}

		return null;
	}

	private static int IndexOfWord(string upper, string word)
	{
		int idx = upper.IndexOf(word, StringComparison.Ordinal);
		if (idx < 0)
		{
			return -1;
		}

		if (idx > 0 && !char.IsWhiteSpace(upper[idx - 1]))
		{
			return -1;
		}

		int after = idx + word.Length;
		if (after < upper.Length && !char.IsWhiteSpace(upper[after]))
		{
			return -1;
		}

		return idx;
	}

	private static QuserSessionRow? TryParseWithLayout(string raw, QuserColumnLayout layout)
	{
		bool isCurrent = false;
		string line = raw;
		if (line.Length > 0 && line[0] == '>')
		{
			isCurrent = true;
			line = ' ' + line[1..];
		}

		// SliceColumn from UserName to SessionName when SessionName is configured,
		// otherwise to ID.
		int userEnd = layout.SessionNameStart >= 0 ? layout.SessionNameStart : layout.IdStart;
		string userName = SliceColumn(line, layout.UserNameStart, userEnd);
		string sessionName = layout.SessionNameStart >= 0
			? SliceColumn(line, layout.SessionNameStart, layout.IdStart)
			: string.Empty;
		// The ID column in quser output is right-justified within a column whose header
		// label is "ID" — so the digit can land at column-end and the STATE column header
		// often sits a few characters past the actual digit. Locate the first all-digit
		// run inside the (idStart .. line end) slice and parse only that, so we are not
		// fooled by a stray "D" leaking in from a state token that starts immediately at
		// the STATE column. After the digit run we walk forward to the next non-whitespace
		// token — that is the canonical STATE value, which works whether the data row's
		// state aligns to the header column or starts immediately after the ID digit.
		string idSlice = SliceColumn(line, layout.IdStart, line.Length);
		if (!TryExtractFirstIntegerAndRemainder(idSlice, out int sessionId, out int afterDigitInSlice))
		{
			return null;
		}

		int afterDigitInLine = layout.IdStart + afterDigitInSlice;
		string state = ExtractFirstToken(line, afterDigitInLine);

		string stateClean = TrimStateToken(state);
		if (stateClean.Length == 0)
		{
			return null;
		}

		string userTrimmed = userName.Trim();
		if (userTrimmed.Length == 0)
		{
			return null;
		}

		return new QuserSessionRow(
			UserName: userTrimmed,
			SessionName: sessionName.Trim(),
			SessionId: sessionId,
			State: stateClean,
			IsCurrent: isCurrent);
	}

	private static string SliceColumn(string line, int start, int end)
	{
		if (start < 0 || start >= line.Length)
		{
			return string.Empty;
		}

		int safeEnd = end < 0 ? line.Length : Math.Min(end, line.Length);
		if (safeEnd <= start)
		{
			return string.Empty;
		}

		return line[start..safeEnd];
	}

	private static string TrimStateToken(string state)
	{
		string trimmed = state.Trim();
		int spaceIdx = trimmed.IndexOf(' ', StringComparison.Ordinal);
		return spaceIdx > 0 ? trimmed[..spaceIdx] : trimmed;
	}

	private static QuserSessionRow? TryParseHeuristic(string raw)
	{
		bool isCurrent = false;
		string line = raw;
		if (line.Length > 0 && line[0] == '>')
		{
			isCurrent = true;
			line = ' ' + line[1..];
		}

		string[] tokens = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
		if (tokens.Length < 3)
		{
			return null;
		}

		// Find the first all-digits token — that is the session ID.
		int idTokenIndex = -1;
		int sessionId = -1;
		for (int i = 0; i < tokens.Length; i++)
		{
			if (IsAllDigits(tokens[i])
				&& int.TryParse(tokens[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
				&& parsed >= 0)
			{
				idTokenIndex = i;
				sessionId = parsed;
				break;
			}
		}

		if (idTokenIndex < 0 || idTokenIndex + 1 >= tokens.Length)
		{
			return null;
		}

		string userName = tokens[0];
		string sessionName = idTokenIndex >= 2 ? tokens[1] : string.Empty;
		string state = tokens[idTokenIndex + 1];

		// Heuristic mode (no English header located) is strictly more error-prone than the
		// layout path, so we accept the row only when the state token is a recognised
		// canonical value — that suppresses generic "ERROR 5 — Access is denied." style
		// lines from being misread as a session row.
		if (!IsRecognisedState(state))
		{
			return null;
		}

		return new QuserSessionRow(
			UserName: userName,
			SessionName: sessionName,
			SessionId: sessionId,
			State: state,
			IsCurrent: isCurrent);
	}

	private static bool TryExtractFirstIntegerAndRemainder(string slice, out int value, out int positionAfter)
	{
		value = -1;
		positionAfter = 0;
		int i = 0;
		while (i < slice.Length && !char.IsDigit(slice[i]))
		{
			i++;
		}

		int start = i;
		while (i < slice.Length && char.IsDigit(slice[i]))
		{
			i++;
		}

		if (i <= start)
		{
			return false;
		}

		string token = slice[start..i];
		positionAfter = i;
		return int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out value) && value >= 0;
	}

	private static string ExtractFirstToken(string line, int startIndex)
	{
		int i = startIndex;
		while (i < line.Length && char.IsWhiteSpace(line[i]))
		{
			i++;
		}

		int tokenStart = i;
		while (i < line.Length && !char.IsWhiteSpace(line[i]))
		{
			i++;
		}

		return i <= tokenStart ? string.Empty : line[tokenStart..i];
	}

	private static bool IsRecognisedState(string token)
	{
		string normalized = QwinstaParser.NormalizeState(token);
		// NormalizeState returns the input verbatim when nothing matches; treat that as
		// "not recognised" and reject. The canonical set covers Active / Connected /
		// Disconnected / Listen / Idle / Shadow / ConnectQuery / Reset / Down / Init plus
		// the localised tokens that map back to those canonical names.
		return !string.Equals(normalized, token, StringComparison.Ordinal)
			|| IsAlreadyCanonical(token);
	}

	private static bool IsAlreadyCanonical(string token)
	{
		switch (token)
		{
			case "Active":
			case "Connected":
			case "Disconnected":
			case "Idle":
			case "Listen":
			case "Shadow":
			case "ConnectQuery":
			case "Reset":
			case "Down":
			case "Init":
				return true;
			default:
				return false;
		}
	}

	private static bool IsAllDigits(string token)
	{
		if (token.Length == 0)
		{
			return false;
		}

		foreach (char c in token)
		{
			if (c < '0' || c > '9')
			{
				return false;
			}
		}

		return true;
	}

	private sealed record QuserColumnLayout(
		int UserNameStart,
		int SessionNameStart,
		int IdStart,
		int StateStart,
		int IdleStart);
}
