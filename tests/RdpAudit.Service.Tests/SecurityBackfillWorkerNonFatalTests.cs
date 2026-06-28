// File:    tests/RdpAudit.Service.Tests/SecurityBackfillWorkerNonFatalTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.1 stabilisation — pin the non-fatal per-id classification contract for
//          SecurityBackfillWorker. A 1102 audit-log-cleared query that times out on a real host
//          while 4624/4625/4776 keep flowing must NOT paint the Security channel as broken at
//          the top level. The previous behaviour set "Last Security channel error" for every
//          per-id QueryFailed, scaring operators into thinking ingestion had stalled when in
//          fact 4624/4625/4776 were still being forwarded.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SecurityBackfillWorkerNonFatalTests
{
	[Theory]
	[InlineData("The operation has timed out", "TimeoutSkipped")]
	[InlineData("Operation timed out while waiting", "TimeoutSkipped")]
	[InlineData("ERROR_TIMEOUT", "TimeoutSkipped")]
	[InlineData("EventLog query timed out reading record 12345", "TimeoutSkipped")]
	[InlineData("Unknown query failure", "QueryFailed")]
	[InlineData(null, "QueryFailed")]
	[InlineData("", "QueryFailed")]
	[InlineData("   ", "QueryFailed")]
	// v1.2.2 — zero-match outcomes must classify as NoEvents, never QueryFailed. This is
	// the canonical EventLogException message PowerShell triage with -ErrorAction Stop
	// surfaces for every id the workstation simply does not produce (4768/4769/4771/4825
	// on a non-DC, 1102 on a host whose audit log has never been cleared, etc.).
	[InlineData("No events were found that match the specified selection criteria.", "NoEvents")]
	[InlineData("no events were found", "NoEvents")]
	[InlineData("There were no matching events for the specified XPath", "NoEvents")]
	// Russian locale — Windows raises the localized form on RU-RU hosts.
	[InlineData("Не найдено событий, соответствующих указанному критерию выбора.", "NoEvents")]
	// German locale.
	[InlineData("Es wurden keine Ereignisse gefunden, die den Kriterien entsprechen.", "NoEvents")]
	public void ClassifyNonFatal_NamesTheSpecificFailure(string? error, string expected)
	{
		Assert.Equal(expected, SecurityBackfillWorker.ClassifyNonFatal(error));
	}

	[Fact]
	public void FormatAggregateStatus_RendersCompactSummary()
	{
		// v1.2.2 — the Diagnostic UI aggregate line must be a single compact string of
		// the form "Forwarded:N, Duplicate:M, NoEvents:K, TimeoutSkipped:T, Failed:F".
		string s = SecurityBackfillWorker.FormatAggregateStatus(12, 8, 10, 0, 0);
		Assert.Equal("Forwarded:12, Duplicate:8, NoEvents:10, TimeoutSkipped:0, Failed:0", s);
	}

	[Theory]
	[InlineData("No events were found that match the specified selection criteria.", true)]
	[InlineData("no matching events", true)]
	[InlineData("Не найдено событий, соответствующих указанному критерию", true)]
	[InlineData("keine Ereignisse gefunden", true)]
	[InlineData("ERROR_TIMEOUT", false)]
	[InlineData("Access denied", false)]
	[InlineData(null, false)]
	[InlineData("", false)]
	public void IsNoEventsMessage_RecognisesLocalizedNoMatchOutcomes(string? message, bool expected)
	{
		Assert.Equal(expected, SecurityBackfillWorker.IsNoEventsMessage(message));
	}
}
