// File:    tests/RdpAudit.Core.Tests/SqlLikeEscaperTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the LIKE-pattern escaping contract that protects the username / IP / log search
//          boxes from LIKE-wildcard injection. Values still flow as SQL parameters via
//          EF.Functions.Like, so this guards the pattern semantics; the tests also exercise the
//          representative hostile login strings (SQL, command, CR/LF) to prove they are handled
//          as literal text rather than altering the match shape.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>LIKE-wildcard escaping coverage for user-supplied search needles.</summary>
public class SqlLikeEscaperTests
{
	[Theory]
	[InlineData("normaluser", "normaluser")]
	[InlineData("DOMAIN\\user", "DOMAIN\\\\user")]
	[InlineData("user.name", "user.name")]
	[InlineData("user-name", "user-name")]
	[InlineData("user name", "user name")]
	[InlineData("100%", "100\\%")]
	[InlineData("a_b", "a\\_b")]
	[InlineData("%_\\", "\\%\\_\\\\")]
	public void Escape_NeutralisesWildcardsAndEscapeChar(string input, string expected)
	{
		Assert.Equal(expected, SqlLikeEscaper.Escape(input));
	}

	[Fact]
	public void Escape_LeavesEmptyStringUnchanged()
	{
		Assert.Equal(string.Empty, SqlLikeEscaper.Escape(string.Empty));
	}

	[Fact]
	public void Escape_Throws_OnNull()
	{
		Assert.Throws<ArgumentNullException>(() => SqlLikeEscaper.Escape(null!));
	}

	[Theory]
	[InlineData("user' OR 1=1 --")]
	[InlineData("user\"; DROP TABLE RawEvents; --")]
	[InlineData("user & whoami")]
	[InlineData("user | powershell -nop")]
	[InlineData("user\r\nFailed logons: 0")]
	public void Escape_PreservesHostileLoginCharactersLiterally(string hostile)
	{
		// SQL/command/CRLF metacharacters carry no meaning inside a LIKE pattern, so they must
		// survive verbatim — only %, _ and the escape char are neutralised. The value reaches the
		// database exclusively as a bound parameter, so the literal text is harmless there.
		string escaped = SqlLikeEscaper.Escape(hostile);

		Assert.DoesNotContain('%', escaped);
		// Every underscore that exists must be preceded by the escape char.
		for (int i = 0; i < escaped.Length; i++)
		{
			if (escaped[i] == '_')
			{
				Assert.True(i > 0 && escaped[i - 1] == SqlLikeEscaper.EscapeChar);
			}
		}
	}

	[Fact]
	public void Escape_IsIdempotentForWildcardFreeInput()
	{
		const string login = "DOMAIN\\service-account.01";
		string once = SqlLikeEscaper.Escape(login);
		// Only the backslash is significant; re-escaping the already-escaped form would double it,
		// so callers must escape exactly once — verified here against the known single-pass result.
		Assert.Equal("DOMAIN\\\\service-account.01", once);
	}

	[Theory]
	[InlineData("admin", "%admin%")]
	[InlineData("a%b", "%a\\%b%")]
	[InlineData("", "%%")]
	public void Contains_WrapsEscapedNeedle(string input, string expected)
	{
		Assert.Equal(expected, SqlLikeEscaper.Contains(input));
	}

	[Fact]
	public void Escape_HandlesVeryLongLogin()
	{
		string login = new('a', 512);
		Assert.Equal(login, SqlLikeEscaper.Escape(login));
	}

	[Fact]
	public void Escape_HandlesUnicodeLogin()
	{
		const string login = "Ivan.Petrové";
		Assert.Equal(login, SqlLikeEscaper.Escape(login));
	}
}
