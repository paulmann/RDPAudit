// File:    src/RdpAudit.Core/Util/QwinstaParser.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure parser for the textual output of "query session" / "qwinsta" used by the
//          Remote RDP Clients tab. Header-agnostic: data rows are detected by the
//          presence of an integer session-id token rather than by English column names,
//          so Russian, English and any other localized Windows output parses identically.
//          When an English header line is present the parser pins the SessionName /
//          UserName / ID / STATE column offsets so empty-session-name rows (a
//          disconnected user with no station) are still attributed to the correct column;
//          when no English header is found (Russian / other localized output) the parser
//          falls back to a pure whitespace heuristic. Robust against the leading
//          "current session" marker (">"), variable inter-column whitespace, missing
//          username columns (services / console / Listen rows) and trailing TYPE/DEVICE
//          columns. Kept free of any Windows-specific APIs so it can be unit-tested
//          cross-platform.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>One row parsed from <c>qwinsta</c> / <c>query session</c> output.</summary>
public sealed record QwinstaSessionRow(
	string SessionName,
	string UserName,
	int SessionId,
	string State,
	bool IsCurrent);

/// <summary>Pure parser for the textual output of <c>qwinsta</c> / <c>query session</c>.</summary>
public static class QwinstaParser
{
	private const int MinColumnGap = 2;
	private const string HeaderSessionName = "SESSIONNAME";
	private const string HeaderUserName = "USERNAME";
	private const string HeaderId = "ID";
	private const string HeaderState = "STATE";

	/// <summary>Parses the combined stdout output of <c>qwinsta</c> regardless of console
	/// language. If an English header is present, the SessionName/UserName/ID/STATE column
	/// offsets are used directly; otherwise data rows are detected by the first
	/// whitespace-separated integer token on the line and split with a whitespace heuristic.
	/// Header lines and noise are skipped automatically. Lines that cannot be parsed are
	/// silently dropped — the parser never throws on operator input.</summary>
	public static IReadOnlyList<QwinstaSessionRow> Parse(string? stdOut)
	{
		List<QwinstaSessionRow> rows = new();
		if (string.IsNullOrWhiteSpace(stdOut))
		{
			return rows;
		}

		string[] lines = stdOut.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
		ColumnLayout? layout = LocateEnglishHeader(lines);

		foreach (string raw in lines)
		{
			string line = raw.TrimEnd();
			if (line.Length == 0)
			{
				continue;
			}

			QwinstaSessionRow? row = layout is not null
				? TryParseWithLayout(line, layout)
				: TryParseHeuristic(line);
			if (row is not null)
			{
				rows.Add(row);
			}
		}

		return rows;
	}

	private static ColumnLayout? LocateEnglishHeader(IReadOnlyList<string> lines)
	{
		foreach (string raw in lines)
		{
			string line = raw.TrimEnd();
			if (line.Length == 0)
			{
				continue;
			}

			string upper = line.ToUpperInvariant();
			int sessionNameCol = IndexOfWord(upper, HeaderSessionName);
			int userNameCol = IndexOfWord(upper, HeaderUserName);
			int idCol = IndexOfWord(upper, HeaderId);
			int stateCol = IndexOfWord(upper, HeaderState);
			if (sessionNameCol < 0 || idCol < 0 || stateCol < 0)
			{
				continue;
			}

			return new ColumnLayout(
				SessionNameStart: sessionNameCol,
				UserNameStart: userNameCol,
				IdStart: idCol,
				StateStart: stateCol);
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

	private static QwinstaSessionRow? TryParseWithLayout(string raw, ColumnLayout layout)
	{
		bool isCurrent = false;
		string line = raw;
		if (line.Length > 0 && line[0] == '>')
		{
			isCurrent = true;
			line = ' ' + line[1..];
		}

		string sessionName = SliceColumn(line, layout.SessionNameStart, layout.UserNameStart);
		string userName = SliceColumn(line, layout.UserNameStart, layout.IdStart);
		string idText = SliceColumn(line, layout.IdStart, layout.StateStart);
		string state = SliceColumn(line, layout.StateStart, line.Length);

		if (string.IsNullOrWhiteSpace(idText)
			|| !int.TryParse(idText.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int sessionId)
			|| sessionId < 0)
		{
			return null;
		}

		string stateClean = TrimStateToken(state);
		if (stateClean.Length == 0)
		{
			return null;
		}

		return new QwinstaSessionRow(
			SessionName: sessionName.Trim(),
			UserName: userName.Trim(),
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

	private static QwinstaSessionRow? TryParseHeuristic(string raw)
	{
		bool isCurrent = false;
		string line = raw;
		if (line.Length > 0 && line[0] == '>')
		{
			isCurrent = true;
			line = ' ' + line[1..];
		}

		if (!TryLocateSessionIdToken(line, out int idStart, out int idEnd, out int sessionId)
			|| sessionId < 0)
		{
			return null;
		}

		string prefix = line[..idStart].TrimEnd();
		string suffix = idEnd >= line.Length ? string.Empty : line[idEnd..].Trim();

		(string sessionName, string userName) = SplitPrefix(prefix);
		string stateToken = ExtractStateToken(suffix);
		if (stateToken.Length == 0)
		{
			return null;
		}

		return new QwinstaSessionRow(
			SessionName: sessionName,
			UserName: userName,
			SessionId: sessionId,
			State: stateToken,
			IsCurrent: isCurrent);
	}

	private static bool TryLocateSessionIdToken(string line, out int start, out int end, out int sessionId)
	{
		start = -1;
		end = -1;
		sessionId = -1;

		int i = 0;
		while (i < line.Length)
		{
			while (i < line.Length && char.IsWhiteSpace(line[i]))
			{
				i++;
			}

			int tokenStart = i;
			while (i < line.Length && !char.IsWhiteSpace(line[i]))
			{
				i++;
			}

			int tokenEnd = i;
			if (tokenEnd <= tokenStart)
			{
				continue;
			}

			string token = line[tokenStart..tokenEnd];
			if (IsAllDigits(token)
				&& int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed))
			{
				start = tokenStart;
				end = tokenEnd;
				sessionId = parsed;
				return true;
			}
		}

		return false;
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

	/// <summary>Splits the pre-id portion of a heuristically-parsed row into
	/// (SessionName, UserName). When the trimmed prefix contains a run of two or more
	/// spaces, that run is treated as the column separator (SessionName + UserName);
	/// otherwise the prefix is treated as the session name with an empty username — the
	/// dominant shape for "services" / "console" / "Listen" rows in localized qwinsta
	/// output.</summary>
	private static (string SessionName, string UserName) SplitPrefix(string prefix)
	{
		string trimmed = prefix.Trim();
		if (trimmed.Length == 0)
		{
			return (string.Empty, string.Empty);
		}

		int gapStart = -1;
		int gapEnd = -1;
		int run = 0;
		for (int i = 0; i < trimmed.Length; i++)
		{
			if (trimmed[i] == ' ')
			{
				if (run == 0)
				{
					gapStart = i;
				}

				run++;
				if (run >= MinColumnGap)
				{
					int j = i + 1;
					while (j < trimmed.Length && trimmed[j] == ' ')
					{
						j++;
					}

					gapEnd = j;
					break;
				}
			}
			else
			{
				run = 0;
				gapStart = -1;
			}
		}

		if (gapStart < 0 || gapEnd < 0)
		{
			return (trimmed, string.Empty);
		}

		string sessionName = trimmed[..gapStart].Trim();
		string userName = trimmed[gapEnd..].Trim();
		return (sessionName, userName);
	}

	private static string ExtractStateToken(string suffix)
	{
		if (suffix.Length == 0)
		{
			return string.Empty;
		}

		int i = 0;
		while (i < suffix.Length && char.IsWhiteSpace(suffix[i]))
		{
			i++;
		}

		int start = i;
		while (i < suffix.Length && !char.IsWhiteSpace(suffix[i]))
		{
			i++;
		}

		return i <= start ? string.Empty : suffix[start..i];
	}

	/// <summary>Maps the raw qwinsta state token to a stable canonical state name
	/// surfaced over IPC. Recognises English Windows output as well as the localized
	/// strings emitted by the Russian-language console (Активно / Подключено / Диск /
	/// Отключено / Прием / Приём). Unknown states are returned verbatim so the row
	/// reaches the operator instead of being silently dropped.</summary>
	public static string NormalizeState(string state)
	{
		if (string.IsNullOrWhiteSpace(state))
		{
			return "Unknown";
		}

		string token = state.Trim();
		string upper = token.ToUpperInvariant();
		switch (upper)
		{
			case "ACTIVE":
				return "Active";
			case "CONN":
			case "CONNECTED":
				return "Connected";
			case "CONNQ":
			case "CONNECTQUERY":
				return "ConnectQuery";
			case "SHADOW":
				return "Shadow";
			case "DISC":
			case "DISCONNECTED":
				return "Disconnected";
			case "IDLE":
				return "Idle";
			case "LISTEN":
				return "Listen";
			case "RESET":
				return "Reset";
			case "DOWN":
				return "Down";
			case "INIT":
				return "Init";
			default:
				return MapLocalizedState(token);
		}
	}

	// Mirrors the WtsStateMap used by the reference qwinsta-en.ps1 script: covers the
	// Russian (Активно / Подключено / Диск / Прием / Тень / Простой), English short
	// (Conn / Disc), and German (Aktiv / Getrennt / Warten) tokens emitted by localized
	// Windows builds. Normalization is OrdinalIgnoreCase so case / encoding artifacts do
	// not block the canonical mapping.
	private static readonly System.Collections.Generic.Dictionary<string, string> LocalizedStateMap =
		new(StringComparer.OrdinalIgnoreCase)
		{
			// Russian
			["Активно"] = "Active",
			["Подключено"] = "Connected",
			["Отключено"] = "Disconnected",
			["Диск"] = "Disconnected",
			["Прием"] = "Listen",
			["Приём"] = "Listen",
			["Простой"] = "Idle",
			["Тень"] = "Shadow",
			["Теневая"] = "Shadow",
			// German
			["Aktiv"] = "Active",
			["Getrennt"] = "Disconnected",
			["Warten"] = "Listen",
			["Verbunden"] = "Connected",
			// English shorthand from older Windows releases
			["Conn"] = "Connected",
			["Disc"] = "Disconnected",
			["Listening"] = "Listen",
			["ConnectQuery"] = "ConnectQuery",
			["ConnQ"] = "ConnectQuery",
		};

	private static string MapLocalizedState(string token)
	{
		return LocalizedStateMap.TryGetValue(token, out string? mapped) ? mapped : token;
	}

	private sealed record ColumnLayout(
		int SessionNameStart,
		int UserNameStart,
		int IdStart,
		int StateStart);
}
