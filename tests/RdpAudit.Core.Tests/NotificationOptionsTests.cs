// File:    tests/RdpAudit.Core.Tests/NotificationOptionsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the Notifications section contract: safe defaults, clamping, severity fallback.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pins the NotificationOptions defaults and clamping behaviour.</summary>
public class NotificationOptionsTests
{
	[Fact]
	public void Defaults_AreEnabledWithSafePolling()
	{
		NotificationOptions options = new();
		Assert.True(options.EnableTrayNotifier);
		Assert.True(options.StartWithWindows);
		Assert.Equal("High", options.MinimumSeverity);
		Assert.Equal(AlertSeverity.High, options.ResolveMinimumSeverity());
		Assert.Equal(5, options.ResolvePollIntervalSeconds());
		Assert.Equal(10, options.ResolveMaxToastsPerMinute());
		Assert.False(options.UseNativeToasts);
		Assert.Empty(options.ShowAlerts);
		Assert.Empty(options.ShowEvents);
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(1, 1)]
	[InlineData(5, 5)]
	[InlineData(60, 60)]
	[InlineData(600, 60)]
	public void ResolvePollIntervalSeconds_ClampsToSupportedRange(int input, int expected)
	{
		NotificationOptions options = new() { PollIntervalSeconds = input };
		Assert.Equal(expected, options.ResolvePollIntervalSeconds());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(1, 1)]
	[InlineData(10, 10)]
	[InlineData(60, 60)]
	[InlineData(600, 60)]
	public void ResolveMaxToastsPerMinute_ClampsToSupportedRange(int input, int expected)
	{
		NotificationOptions options = new() { MaxToastsPerMinute = input };
		Assert.Equal(expected, options.ResolveMaxToastsPerMinute());
	}

	[Theory]
	[InlineData("", AlertSeverity.High)]
	[InlineData("bogus", AlertSeverity.High)]
	[InlineData("critical", AlertSeverity.Critical)]
	[InlineData("info", AlertSeverity.Info)]
	[InlineData("LOW", AlertSeverity.Low)]
	public void ResolveMinimumSeverity_ParsesOrFallsBack(string input, AlertSeverity expected)
	{
		NotificationOptions options = new() { MinimumSeverity = input };
		Assert.Equal(expected, options.ResolveMinimumSeverity());
	}
}
