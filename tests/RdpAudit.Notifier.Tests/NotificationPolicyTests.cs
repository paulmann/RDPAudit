// File:    tests/RdpAudit.Notifier.Tests/NotificationPolicyTests.cs
// Module:  RdpAudit.Notifier.Tests
// Purpose: Locks policy resolution from the IPC DTO: clamping, severity fallback, defaults.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Notifier.Notifications;
using Xunit;

namespace RdpAudit.Notifier.Tests;

/// <summary>Pins NotificationPolicy resolution behaviour.</summary>
public class NotificationPolicyTests
{
	[Fact]
	public void Defaults_AreEnabledWithSafeBounds()
	{
		NotificationPolicy policy = NotificationPolicy.Defaults();
		Assert.True(policy.Enabled);
		Assert.Equal(5, policy.PollIntervalSeconds);
		Assert.Equal(AlertSeverity.High, policy.MinimumSeverity);
		Assert.Equal(10, policy.MaximumToastsPerMinute);
	}

	[Fact]
	public void From_ClampsPollAndToastBounds()
	{
		NotificationSettingsDto dto = new()
		{
			PollIntervalSeconds = 999,
			MaxToastsPerMinute = 0,
		};

		NotificationPolicy policy = NotificationPolicy.From(dto);
		Assert.Equal(60, policy.PollIntervalSeconds);
		Assert.Equal(1, policy.MaximumToastsPerMinute);
	}

	[Theory]
	[InlineData("", AlertSeverity.High)]
	[InlineData("bogus", AlertSeverity.High)]
	[InlineData("low", AlertSeverity.Low)]
	[InlineData("CRITICAL", AlertSeverity.Critical)]
	public void From_ParsesSeverityOrFallsBack(string input, AlertSeverity expected)
	{
		NotificationSettingsDto dto = new() { MinimumSeverity = input };
		Assert.Equal(expected, NotificationPolicy.From(dto).MinimumSeverity);
	}

	[Fact]
	public void From_CarriesNativeToastPreference()
	{
		NotificationSettingsDto dto = new() { UseNativeToasts = true };
		Assert.True(NotificationPolicy.From(dto).UseNativeToasts);
	}

	[Fact]
	public void From_CarriesEnabledAndRuleMap()
	{
		NotificationSettingsDto dto = new()
		{
			EnableTrayNotifier = false,
			ShowAlerts = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase) { ["BRUTE_FORCE"] = false },
		};

		NotificationPolicy policy = NotificationPolicy.From(dto);
		Assert.False(policy.Enabled);
		Assert.Contains("BRUTE_FORCE", policy.ShowAlerts.Keys);
	}
}
