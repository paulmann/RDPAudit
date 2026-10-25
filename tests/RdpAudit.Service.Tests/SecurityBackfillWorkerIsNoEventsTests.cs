/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : SecurityBackfillWorkerIsNoEventsTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Regression coverage for SecurityBackfillWorker.IsNoEventsMessage classification and
//          for the structural shape of the per-EventID XPath used by the backfill worker.
// Depends: SecurityBackfillWorker, SecurityAuthQuery, Xunit
// Extends: Add new localized "no matching events" message variants here when discovered.

using Xunit;
using RdpAudit.Core.Events;
using RdpAudit.Service.Workers;

namespace RdpAudit.Service.Tests.Workers;

public sealed class SecurityBackfillWorkerIsNoEventsTests
{
	[Theory]
	[InlineData("No events were found that match the specified selection criteria.")]
	[InlineData("Element not found")]
	[InlineData("ERROR_NOT_FOUND")]
	[InlineData("0x490")]
	[InlineData("Не найдено событий, соответствующих указанному критерию выбора.")]
	[InlineData("keine Ereignisse gefunden")]
	public void IsNoEventsMessage_ReturnsTrue_ForAllKnownVariants(string message)
	{
		Assert.True(SecurityBackfillWorker.IsNoEventsMessage(message));
	}

	[Fact]
	public void IsNoEventsMessage_ReturnsFalse_ForAccessDenied()
	{
		Assert.False(SecurityBackfillWorker.IsNoEventsMessage("Access is denied."));
	}

	[Fact]
	public void BuildXPathSingleId_4647_IsStructurallyIdenticalTo_4634()
	{
		DateTime since = new(2026, 7, 2, 12, 0, 0, DateTimeKind.Utc);
		string xpath4647 = SecurityAuthQuery.BuildXPathSingleId(4647, since);
		string xpath4634 = SecurityAuthQuery.BuildXPathSingleId(4634, since);

		Assert.Matches(@"\*\[System\[\(EventID=4647\)", xpath4647);
		Assert.Matches(@"\*\[System\[\(EventID=4634\)", xpath4634);
		Assert.Equal(
			xpath4647.Replace("4647", "X"),
			xpath4634.Replace("4634", "X"));
	}
}
