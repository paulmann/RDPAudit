// File:    tests/RdpAudit.Core.Tests/QwinstaParserTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the QwinstaParser against representative qwinsta / query-session
//          outputs, including the current-session marker, header variants, disconnected
//          rows that are missing the session-name column, and the Russian-language
//          (Cyrillic) output reported in the field when the operator's console runs
//          under a non-English Windows UI culture. The parser is header-agnostic when no
//          English header is present so the operator still sees their live RDP sessions
//          on localized hosts.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class QwinstaParserTests
{
	[Fact]
	public void Parse_TypicalOutput_ProducesExpectedRows()
	{
		const string sample =
			" SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\n" +
			" services                                    0  Disc                        \n" +
			" console           alice                     1  Active                      \n" +
			" rdp-tcp#3         bob                       3  Active  rdpwd               \n" +
			"                   carol                     4  Disc                        \n" +
			" rdp-tcp                                 65536  Listen                      \n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);

		Assert.NotEmpty(rows);
		// Listen row with id 65536 (over our validator cap) should still be parsed by the pure
		// parser — the validator lives at the command-builder layer.
		Assert.Contains(rows, r => r.SessionId == 1 && r.UserName == "alice");
		Assert.Contains(rows, r => r.SessionId == 3 && r.UserName == "bob");
		Assert.Contains(rows, r => r.SessionId == 4 && r.UserName == "carol");
		Assert.Contains(rows, r => r.SessionId == 0);
	}

	[Fact]
	public void Parse_CurrentSessionMarker_FlagsRow()
	{
		const string sample =
			" SESSIONNAME       USERNAME                 ID  STATE\n" +
			">rdp-tcp#7         alice                     7  Active\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		QwinstaSessionRow row = Assert.Single(rows);
		Assert.True(row.IsCurrent);
		Assert.Equal(7, row.SessionId);
		Assert.Equal("alice", row.UserName);
	}

	[Fact]
	public void Parse_ExtraWhitespace_StillFindsColumns()
	{
		const string sample =
			"     SESSIONNAME             USERNAME                          ID   STATE\n" +
			"     rdp-tcp#1               admin                              2   Active\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		QwinstaSessionRow row = Assert.Single(rows);
		Assert.Equal(2, row.SessionId);
		Assert.Equal("admin", row.UserName);
		Assert.Equal("Active", row.State);
	}

	[Fact]
	public void Parse_EmptyInput_ReturnsEmpty()
	{
		Assert.Empty(QwinstaParser.Parse(string.Empty));
		Assert.Empty(QwinstaParser.Parse(null));
		Assert.Empty(QwinstaParser.Parse("    \n   \n"));
	}

	[Fact]
	public void Parse_UnrecognisableHeader_NoIntegerIds_ReturnsEmpty()
	{
		Assert.Empty(QwinstaParser.Parse("garbage line one\ngarbage line two\n"));
	}

	[Theory]
	[InlineData("Active", "Active")]
	[InlineData("Disc", "Disconnected")]
	[InlineData("Conn", "Connected")]
	[InlineData("Listen", "Listen")]
	[InlineData("Down", "Down")]
	[InlineData("ConnQ", "ConnectQuery")]
	[InlineData("unknown", "unknown")]
	[InlineData("", "Unknown")]
	[InlineData("Активно", "Active")]
	[InlineData("Подключено", "Connected")]
	[InlineData("Диск", "Disconnected")]
	[InlineData("Отключено", "Disconnected")]
	[InlineData("Прием", "Listen")]
	[InlineData("Приём", "Listen")]
	public void NormalizeState_MapsKnownTokens(string input, string expected)
	{
		Assert.Equal(expected, QwinstaParser.NormalizeState(input));
	}

	// ---------------------------------------------------------------------------------------------
	// Stage 7 — Russian-language qwinsta output. The user's failing local sample reads as below
	// once captured from a Russian Windows host; the page must still surface the two active RDP
	// sessions (rdp-tcp#1 / af / id 2 and rdp-tcp#21 / md / id 3) so the operator does not have
	// to read raw qwinsta themselves. The current-session marker (">") on the md row must be
	// preserved.
	// ---------------------------------------------------------------------------------------------

	[Fact]
	public void Parse_RussianSample_ProducesActiveRdpRows()
	{
		const string sample =
			" СЕАНС             ПОЛЬЗОВАТЕЛЬ             ID  СТАТУС  ТИП         УСТР-ВО\n" +
			" services                                    0  Диск\n" +
			" console                                     1  Подключено\n" +
			" rdp-tcp#1         af                        2  Активно\n" +
			">rdp-tcp#21        md                        3  Активно\n" +
			" 31c5ce94259d4...                        65536  Прием\n" +
			" rdp-tcp                                 65537  Прием\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);

		QwinstaSessionRow af = Assert.Single(rows, r => r.SessionId == 2);
		Assert.Equal("af", af.UserName);
		Assert.Equal("rdp-tcp#1", af.SessionName);
		Assert.Equal("Активно", af.State);
		Assert.False(af.IsCurrent);

		QwinstaSessionRow md = Assert.Single(rows, r => r.SessionId == 3);
		Assert.Equal("md", md.UserName);
		Assert.Equal("rdp-tcp#21", md.SessionName);
		Assert.Equal("Активно", md.State);
		Assert.True(md.IsCurrent);

		Assert.Contains(rows, r => r.SessionId == 0 && r.SessionName == "services" && r.State == "Диск");
		Assert.Contains(rows, r => r.SessionId == 1 && r.SessionName == "console" && r.State == "Подключено");
		Assert.Contains(rows, r => r.SessionId == 65536 && r.State == "Прием");
		Assert.Contains(rows, r => r.SessionId == 65537 && r.SessionName == "rdp-tcp" && r.State == "Прием");
	}

	[Fact]
	public void Parse_EnglishSampleEquivalent_ProducesSameLogicalRows()
	{
		// Same shape as the Russian sample above but emitted by an English-language qwinsta
		// (column header English, state tokens English). The two paths must produce identical
		// SessionId / UserName / SessionName fields so the page renders the same row set.
		const string sample =
			" SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\n" +
			" services                                    0  Disc\n" +
			" console                                     1  Conn\n" +
			" rdp-tcp#1         af                        2  Active\n" +
			">rdp-tcp#21        md                        3  Active\n" +
			" 31c5ce94259d4...                        65536  Listen\n" +
			" rdp-tcp                                 65537  Listen\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);

		QwinstaSessionRow af = Assert.Single(rows, r => r.SessionId == 2);
		Assert.Equal("af", af.UserName);
		Assert.Equal("rdp-tcp#1", af.SessionName);
		Assert.Equal("Active", af.State);

		QwinstaSessionRow md = Assert.Single(rows, r => r.SessionId == 3);
		Assert.Equal("md", md.UserName);
		Assert.True(md.IsCurrent);
		Assert.Equal("Active", md.State);
	}

	[Fact]
	public void Parse_RussianSample_ActiveRowsMapToCanonicalActiveState()
	{
		const string sample =
			" СЕАНС             ПОЛЬЗОВАТЕЛЬ             ID  СТАТУС\n" +
			" rdp-tcp#1         af                        2  Активно\n" +
			">rdp-tcp#21        md                        3  Активно\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		foreach (QwinstaSessionRow row in rows)
		{
			Assert.Equal("Active", QwinstaParser.NormalizeState(row.State));
		}
	}

	[Fact]
	public void Parse_LeadingCurrentMarker_OnRussianRow_IsStripped()
	{
		const string sample =
			">rdp-tcp#21        md                        3  Активно\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		QwinstaSessionRow row = Assert.Single(rows);
		Assert.True(row.IsCurrent);
		Assert.Equal("rdp-tcp#21", row.SessionName);
		Assert.Equal("md", row.UserName);
		Assert.Equal(3, row.SessionId);
	}

	[Fact]
	public void Parse_HeaderLanguageDoesNotMatter_WhenIntegerIdsArePresent()
	{
		// Truly unknown header tokens. As long as an integer session-id token appears on data
		// rows the parser must surface them so a future Windows locale (Portuguese / Polish /
		// any other) is not silently filtered out.
		const string sample =
			" XYZHEADER         FOOHEADER                ABCD STATEFOO\n" +
			" rdp-tcp#9         alice                     9   SomeStateInUnknownLanguage\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		QwinstaSessionRow row = Assert.Single(rows);
		Assert.Equal(9, row.SessionId);
		Assert.Equal("alice", row.UserName);
		Assert.Equal("rdp-tcp#9", row.SessionName);
		Assert.Equal("SomeStateInUnknownLanguage", row.State);
	}

	[Fact]
	public void Parse_LocalizedActiveState_IsNotFilteredOut_AtMapperLayer()
	{
		// Guard against a future regression where the page filters rows by State == "Active".
		// QwinstaSessionMapper must normalize "Активно" to canonical "Active" so the UI's
		// IsActive predicate fires correctly. This test pulls in the mapper directly to make
		// the contract explicit.
		QwinstaSessionRow row = new("rdp-tcp#1", "af", 2, "Активно", false);
		RdpAudit.Core.Ipc.Contracts.RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.Equal("Active", dto.State);
		Assert.True(dto.IsActive);
	}

	[Fact]
	public void Parse_RowWithNoUserNameAndNoEnglishHeader_KeepsSessionName()
	{
		// Localized listen / services rows: the only token before the integer is the session
		// name and there is no user column. The heuristic must not promote that token into the
		// user column or drop the row.
		const string sample =
			" СЕАНС             ПОЛЬЗОВАТЕЛЬ             ID  СТАТУС\n" +
			" services                                    0  Диск\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		QwinstaSessionRow row = Assert.Single(rows);
		Assert.Equal(0, row.SessionId);
		Assert.Equal("services", row.SessionName);
		Assert.Equal(string.Empty, row.UserName);
		Assert.Equal("Диск", row.State);
	}

	[Fact]
	public void Parse_UnknownState_DoesNotDropRow()
	{
		// Critical invariant: an unknown / future state must not cause the parser to filter
		// the row out. The UI then displays the row with the raw state and the user can still
		// act on it.
		const string sample =
			" СЕАНС             ПОЛЬЗОВАТЕЛЬ             ID  СТАТУС\n" +
			" rdp-tcp#5         eve                       5  СовершенноНовоеСостояние\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		QwinstaSessionRow row = Assert.Single(rows);
		Assert.Equal(5, row.SessionId);
		Assert.Equal("eve", row.UserName);
	}
}
