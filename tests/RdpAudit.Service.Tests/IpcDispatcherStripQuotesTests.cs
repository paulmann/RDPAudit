// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStripQuotesTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Pins the defensive address sanitiser used by the Remove-from-blocklist IPC handler. A grid
//          binding that double-serialized the selected address could arrive wrapped in single or
//          double quotes (e.g. "\"80.244.40.164\""); StripSurroundingQuotes must peel exactly one
//          matched outer pair and trim, so the subsequent IP normalization/equality lookup matches the
//          stored row instead of silently finding nothing.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Ipc;
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStripQuotesTests
{
	[Theory]
	[InlineData("80.244.40.164", "80.244.40.164")]
	[InlineData("\"80.244.40.164\"", "80.244.40.164")]
	[InlineData("'80.244.40.164'", "80.244.40.164")]
	[InlineData("  80.244.40.164  ", "80.244.40.164")]
	[InlineData("\" 80.244.40.164 \"", "80.244.40.164")]
	public void StripSurroundingQuotes_RemovesOneMatchedOuterPair_AndTrims(string input, string expected)
	{
		Assert.Equal(expected, IpcDispatcher.StripSurroundingQuotes(input));
	}

	[Theory]
	[InlineData("\"80.244.40.164'", "\"80.244.40.164'")]
	[InlineData("80.244.40.164\"", "80.244.40.164\"")]
	[InlineData("'80.244.40.164", "'80.244.40.164")]
	public void StripSurroundingQuotes_LeavesMismatchedOrSingleSidedQuotes(string input, string expected)
	{
		Assert.Equal(expected, IpcDispatcher.StripSurroundingQuotes(input));
	}
}
