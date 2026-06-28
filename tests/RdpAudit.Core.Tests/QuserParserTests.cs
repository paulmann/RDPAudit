// File:    tests/RdpAudit.Core.Tests/QuserParserTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates QuserParser against the operator's exact field-reported sample (English
//          STATE tokens from a Russian-locale Windows host via chcp 437) and the typical
//          quser output shapes — including the "current session" marker, missing
//          SESSIONNAME column, and trailing IDLE TIME / LOGON TIME columns. The pure parser
//          is the canonical input to QwinstaQuserMerger, so its column-attribution rules
//          are exercised exhaustively here.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class QuserParserTests
{
	[Fact]
	public void Parse_OperatorSample_ExtractsBothUsers()
	{
		const string sample =
			" USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n"
			+ " af                                       2  Disc       none    2026-05-26 10:00\n"
			+ " md                    rdp-tcp#26         3  Active        .    2026-05-26 11:23\n";

		IReadOnlyList<QuserSessionRow> rows = QuserParser.Parse(sample);

		Assert.Equal(2, rows.Count);
		QuserSessionRow af = Assert.Single(rows, r => r.UserName == "af");
		Assert.Equal(2, af.SessionId);
		Assert.Equal("Disc", af.State);
		// Blank sessionname when qwinsta left it blank — quser may also report it blank
		// since it shares the same WTS metadata. The parser must not invent a value.
		Assert.True(string.IsNullOrEmpty(af.SessionName));

		QuserSessionRow md = Assert.Single(rows, r => r.UserName == "md");
		Assert.Equal(3, md.SessionId);
		Assert.Equal("Active", md.State);
		Assert.Equal("rdp-tcp#26", md.SessionName);
	}

	[Fact]
	public void Parse_CurrentSessionMarker_FlagsRow()
	{
		const string sample =
			" USERNAME    SESSIONNAME   ID  STATE   IDLE TIME  LOGON TIME\n"
			+ ">alice       rdp-tcp#7     7  Active        .    2026-05-25 09:00\n";

		QuserSessionRow row = Assert.Single(QuserParser.Parse(sample));
		Assert.True(row.IsCurrent);
		Assert.Equal("alice", row.UserName);
		Assert.Equal(7, row.SessionId);
		Assert.Equal("Active", row.State);
	}

	[Fact]
	public void Parse_EmptyOrWhitespaceInput_ReturnsEmpty()
	{
		Assert.Empty(QuserParser.Parse(string.Empty));
		Assert.Empty(QuserParser.Parse(null));
		Assert.Empty(QuserParser.Parse("    \n   \n"));
	}

	[Fact]
	public void Parse_NoIntegerColumns_ReturnsEmpty()
	{
		const string sample = "ERROR 5 — Access is denied.\n";
		Assert.Empty(QuserParser.Parse(sample));
	}

	[Fact]
	public void Parse_HeuristicFallback_ParsesPlainTokenStream()
	{
		// No English header — exercise the heuristic fallback. The token immediately
		// before the first all-digits token is the SESSIONNAME; the first token is the
		// USERNAME; the token immediately after the digits is the STATE.
		const string sample = " bob   rdp-tcp#9   9   Active   none   2026-05-26 12:00\n";
		QuserSessionRow row = Assert.Single(QuserParser.Parse(sample));
		Assert.Equal("bob", row.UserName);
		Assert.Equal(9, row.SessionId);
		Assert.Equal("Active", row.State);
	}
}
