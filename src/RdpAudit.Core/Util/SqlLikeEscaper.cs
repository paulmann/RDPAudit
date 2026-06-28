// File:    src/RdpAudit.Core/Util/SqlLikeEscaper.cs
// Module:  RdpAudit.Core.Util
// Purpose: Escapes user-supplied search text so its LIKE wildcards (% and _) are matched
//          literally, preventing LIKE-pattern injection through username / IP / log search
//          boxes. Values still travel as SQL parameters via EF.Functions.Like, so this guards
//          the pattern semantics, not SQL injection.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>
/// Escapes user-supplied search text so SQL LIKE wildcards are treated literally.
/// </summary>
public static class SqlLikeEscaper
{
	/// <summary>
	/// The escape character paired with the <c>ESCAPE</c> clause of a LIKE expression.
	/// </summary>
	public const char EscapeChar = '\\';

	/// <summary>
	/// The escape character as a single-character string, matching the <c>string escapeCharacter</c>
	/// parameter of <c>EF.Functions.Like(value, pattern, escapeCharacter)</c> in EF Core.
	/// </summary>
	public const string EscapeString = "\\";

	/// <summary>
	/// Escapes the LIKE-significant characters (the escape character itself, <c>%</c> and <c>_</c>)
	/// in <paramref name="value"/> so they match literally rather than as wildcards.
	/// </summary>
	/// <param name="value">The raw, user-supplied needle. May be empty.</param>
	/// <returns>The escaped needle, safe to embed inside a <c>%...%</c> contains pattern.</returns>
	public static string Escape(string value)
	{
		ArgumentNullException.ThrowIfNull(value);

		if (value.Length == 0)
		{
			return value;
		}

		// Escape the escape character first so we never double-escape a wildcard's prefix.
		System.Text.StringBuilder sb = new(value.Length + 8);
		foreach (char c in value)
		{
			if (c == EscapeChar || c == '%' || c == '_')
			{
				sb.Append(EscapeChar);
			}

			sb.Append(c);
		}

		return sb.ToString();
	}

	/// <summary>
	/// Builds a wildcard-escaped <c>%needle%</c> "contains" pattern from raw user input, ready to
	/// pass as the pattern argument of <c>EF.Functions.Like(value, pattern, EscapeChar)</c>.
	/// </summary>
	/// <param name="value">The raw, user-supplied needle.</param>
	/// <returns>A contains pattern whose embedded wildcards are neutralised.</returns>
	public static string Contains(string value) => "%" + Escape(value) + "%";
}
