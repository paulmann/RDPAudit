// File:    tests/RdpAudit.Notifier.Tests/NotificationFilterTests.cs
// Module:  RdpAudit.Notifier.Tests
// Purpose: Locks the filter contract: severity gate, per-rule visibility, id deduplication.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;
using RdpAudit.Notifier.Notifications;
using Xunit;

namespace RdpAudit.Notifier.Tests;

/// <summary>Pins NotificationFilter decision logic.</summary>
public class NotificationFilterTests
{
	private static Alert Alert(long id, AlertSeverity severity, string ruleId = "RULE")
		=> new() { Id = id, Severity = severity, RuleId = ruleId, Message = "msg" };

	[Fact]
	public void DisabledPolicy_SelectsNothing()
	{
		NotificationFilter filter = new();
		NotificationPolicy policy = NotificationPolicy.Defaults() with { Enabled = false };
		Assert.Empty(filter.SelectNew([Alert(1, AlertSeverity.Critical)], policy));
	}

	[Fact]
	public void BelowSeverity_IsSkipped()
	{
		NotificationFilter filter = new();
		NotificationPolicy policy = NotificationPolicy.Defaults() with { MinimumSeverity = AlertSeverity.High };
		Assert.Empty(filter.SelectNew([Alert(1, AlertSeverity.Medium)], policy));
	}

	[Fact]
	public void RuleHidden_IsSkipped()
	{
		NotificationFilter filter = new();
		NotificationPolicy policy = NotificationPolicy.Defaults() with
		{
			ShowAlerts = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase) { ["RULE"] = false },
		};
		Assert.Empty(filter.SelectNew([Alert(1, AlertSeverity.High)], policy));
	}

	[Fact]
	public void DuplicateIds_AreShownOnce()
	{
		NotificationFilter filter = new();
		NotificationPolicy policy = NotificationPolicy.Defaults();
		List<Alert> batch = [Alert(1, AlertSeverity.High), Alert(1, AlertSeverity.High)];
		Assert.Single(filter.SelectNew(batch, policy));
		Assert.Empty(filter.SelectNew(batch, policy));
	}

	[Fact]
	public void Selected_AreNewestFirst()
	{
		NotificationFilter filter = new();
		NotificationPolicy policy = NotificationPolicy.Defaults();
		List<Alert> selected = filter.SelectNew(
			[Alert(1, AlertSeverity.High), Alert(3, AlertSeverity.Critical), Alert(2, AlertSeverity.High)],
			policy);
		Assert.Equal([3L, 2L, 1L], selected.Select(a => a.Id));
	}

	[Fact]
	public void Reset_AllowsReDelivery()
	{
		NotificationFilter filter = new();
		NotificationPolicy policy = NotificationPolicy.Defaults();
		List<Alert> batch = [Alert(1, AlertSeverity.High)];
		Assert.Single(filter.SelectNew(batch, policy));
		filter.Reset();
		Assert.Single(filter.SelectNew(batch, policy));
	}
}
