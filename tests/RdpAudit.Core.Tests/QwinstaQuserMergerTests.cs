// File:    tests/RdpAudit.Core.Tests/QwinstaQuserMergerTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the QwinstaQuserMerger using the operator's exact field-reported
//          combination of qwinsta + quser output: qwinsta emits a row with blank SESSIONNAME
//          for user "af" id 2 Disc, plus rdp-tcp#26 for user "md" id 3 Active; quser reports
//          both users with id/state matching qwinsta. The merger must fill the blank
//          SessionName on the af row using quser data, and must NOT add any new rows or
//          touch the rdp-tcp#26 row.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Generic;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class QwinstaQuserMergerTests
{
	[Fact]
	public void Merge_OperatorSample_RepairsBlankSessionName()
	{
		const string qwinstaSample =
			" SESSIONNAME       USERNAME              ID  STATE   TYPE        DEVICE\n"
			+ " services                                 0  Disc                        \n"
			+ " console                                  1  Conn                        \n"
			+ "                   af                     2  Disc                        \n"
			+ " rdp-tcp#26         md                    3  Active                      \n"
			+ " rdp-tcp                              65536  Listen                      \n"
			+ " rdp-tcp                              65537  Listen                      \n";

		// quser uses different column layout — the parser handles it; here we model the
		// output the operator reported in the diagnostic.
		const string quserSample =
			" USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n"
			+ " af                    rdp-tcp#5          2  Disc       none    2026-05-26 10:00\n"
			+ " md                    rdp-tcp#26         3  Active        .    2026-05-26 11:23\n";

		List<QwinstaSessionRow> qwinstaRows = new(QwinstaParser.Parse(qwinstaSample));
		IReadOnlyList<QuserSessionRow> quserRows = QuserParser.Parse(quserSample);

		QwinstaQuserMergeResult result = QwinstaQuserMerger.Merge(qwinstaRows, quserRows);

		Assert.Equal(1, result.RowsAugmented);

		QwinstaSessionRow afRow = Assert.Single(qwinstaRows, r => r.SessionId == 2);
		Assert.Equal("rdp-tcp#5", afRow.SessionName);
		Assert.Equal("af", afRow.UserName);

		QwinstaSessionRow mdRow = Assert.Single(qwinstaRows, r => r.SessionId == 3);
		Assert.Equal("rdp-tcp#26", mdRow.SessionName);
		Assert.Equal("md", mdRow.UserName);
	}

	[Fact]
	public void Merge_NoMatchingQuserRow_DoesNotAugment()
	{
		List<QwinstaSessionRow> qwinstaRows = new()
		{
			new QwinstaSessionRow(SessionName: string.Empty, UserName: "alice", SessionId: 2, State: "Disc", IsCurrent: false),
		};
		IReadOnlyList<QuserSessionRow> quserRows = System.Array.Empty<QuserSessionRow>();

		QwinstaQuserMergeResult result = QwinstaQuserMerger.Merge(qwinstaRows, quserRows);
		Assert.Equal(0, result.RowsAugmented);
		Assert.Equal(string.Empty, qwinstaRows[0].SessionName);
	}

	[Fact]
	public void Merge_DifferentState_DoesNotAugment()
	{
		List<QwinstaSessionRow> qwinstaRows = new()
		{
			new QwinstaSessionRow(SessionName: string.Empty, UserName: "alice", SessionId: 2, State: "Disc", IsCurrent: false),
		};
		IReadOnlyList<QuserSessionRow> quserRows = new[]
		{
			new QuserSessionRow(UserName: "alice", SessionName: "rdp-tcp#5", SessionId: 2, State: "Active", IsCurrent: false),
		};

		QwinstaQuserMergeResult result = QwinstaQuserMerger.Merge(qwinstaRows, quserRows);
		Assert.Equal(0, result.RowsAugmented);
	}

	[Fact]
	public void Merge_SessionNameAlreadyPresent_DoesNotOverwrite()
	{
		List<QwinstaSessionRow> qwinstaRows = new()
		{
			new QwinstaSessionRow(SessionName: "rdp-tcp#9", UserName: "alice", SessionId: 9, State: "Active", IsCurrent: false),
		};
		IReadOnlyList<QuserSessionRow> quserRows = new[]
		{
			new QuserSessionRow(UserName: "alice", SessionName: "rdp-tcp#99", SessionId: 9, State: "Active", IsCurrent: false),
		};

		QwinstaQuserMergeResult result = QwinstaQuserMerger.Merge(qwinstaRows, quserRows);
		Assert.Equal(0, result.RowsAugmented);
		Assert.Equal("rdp-tcp#9", qwinstaRows[0].SessionName);
	}

	[Fact]
	public void Merge_AmbiguousMultipleQuserRowsMatchingSameSession_DoesNotAugment()
	{
		List<QwinstaSessionRow> qwinstaRows = new()
		{
			new QwinstaSessionRow(SessionName: string.Empty, UserName: "alice", SessionId: 2, State: "Disc", IsCurrent: false),
		};
		IReadOnlyList<QuserSessionRow> quserRows = new[]
		{
			new QuserSessionRow(UserName: "alice", SessionName: "rdp-tcp#1", SessionId: 2, State: "Disc", IsCurrent: false),
			new QuserSessionRow(UserName: "alice", SessionName: "rdp-tcp#2", SessionId: 2, State: "Disc", IsCurrent: false),
		};

		QwinstaQuserMergeResult result = QwinstaQuserMerger.Merge(qwinstaRows, quserRows);
		Assert.Equal(0, result.RowsAugmented);
	}

	[Fact]
	public void Merge_NormalizesStateBeforeMatching_DiscAndDisconnectedAreEqual()
	{
		List<QwinstaSessionRow> qwinstaRows = new()
		{
			new QwinstaSessionRow(SessionName: string.Empty, UserName: "alice", SessionId: 2, State: "Disc", IsCurrent: false),
		};
		IReadOnlyList<QuserSessionRow> quserRows = new[]
		{
			new QuserSessionRow(UserName: "alice", SessionName: "rdp-tcp#5", SessionId: 2, State: "Disconnected", IsCurrent: false),
		};

		QwinstaQuserMergeResult result = QwinstaQuserMerger.Merge(qwinstaRows, quserRows);
		Assert.Equal(1, result.RowsAugmented);
		Assert.Equal("rdp-tcp#5", qwinstaRows[0].SessionName);
	}
}
