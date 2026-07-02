// Version: 2.0.1
// RdpAudit.Service.Tests/Workers/SecurityBackfillWorkerIsNoEventsTests.cs

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
	// Regression: XPath for 4647 must not differ structurally from 4634.
	DateTime since = new(2026, 7, 2, 12, 0, 0, DateTimeKind.Utc);
	string xpath4647 = SecurityAuthQuery.BuildXPathSingleId(4647, since);
	string xpath4634 = SecurityAuthQuery.BuildXPathSingleId(4634, since);
	// Both must match the pattern *[System[(EventID=N) and TimeCreated[...]]]
	Assert.Matches(@"\*\[System\[\(EventID=4647\)", xpath4647);
	Assert.Matches(@"\*\[System\[\(EventID=4634\)", xpath4634);
	// Structure must be identical modulo the event ID itself.
	Assert.Equal(
		xpath4647.Replace("4647", "X"),
		xpath4634.Replace("4634", "X"));
}
