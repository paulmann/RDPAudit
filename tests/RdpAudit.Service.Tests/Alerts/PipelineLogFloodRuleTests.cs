/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : PipelineLogFloodRuleTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Alerts)
// Purpose: Verifies delta-based monitoring-pipeline flood alerts, cooldown suppression, and enablement behavior.
// Depends: xUnit, PipelineLogFloodRule, ServiceMetrics, MockAlertContext
// Extends: Add a test when a new pipeline pressure metric is included in the alert delta.

using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using RdpAudit.Service.Alerts;
using Xunit;

namespace RdpAudit.Service.Tests.Alerts;

public sealed class PipelineLogFloodRuleTests
{
	[Fact]
	public async Task DeltaAboveThreshold_ReturnsAlert()
	{
		ServiceMetrics metrics = new();
		PipelineLogFloodRule rule = new(metrics, new AlertCooldownTracker());
		MockAlertContext context = CreateContext(threshold: 3);

		IncrementOverflows(metrics, 3);

		Alert? alert = await rule.EvaluateAsync(CreateTriggerEvent(), context, CancellationToken.None);

		Assert.NotNull(alert);
		Assert.Equal("PIPELINE_LOG_FLOOD", alert!.RuleId);
	}

	[Fact]
	public async Task DeltaBelowThreshold_ReturnsNull()
	{
		ServiceMetrics metrics = new();
		PipelineLogFloodRule rule = new(metrics, new AlertCooldownTracker());
		MockAlertContext context = CreateContext(threshold: 3);

		IncrementOverflows(metrics, 2);

		Alert? alert = await rule.EvaluateAsync(CreateTriggerEvent(), context, CancellationToken.None);

		Assert.Null(alert);
	}

	[Fact]
	public async Task Cooldown_SuppressesRepeatedFloodAlert()
	{
		ServiceMetrics metrics = new();
		PipelineLogFloodRule rule = new(metrics, new AlertCooldownTracker());
		MockAlertContext context = CreateContext(threshold: 2);

		IncrementOverflows(metrics, 2);
		Alert? firstAlert = await rule.EvaluateAsync(CreateTriggerEvent(), context, CancellationToken.None);

		IncrementOverflows(metrics, 2);
		Alert? repeatedAlert = await rule.EvaluateAsync(CreateTriggerEvent(), context, CancellationToken.None);

		Assert.NotNull(firstAlert);
		Assert.Null(repeatedAlert);
	}

	[Fact]
	public async Task DisabledOption_PreventsEvaluation()
	{
		ServiceMetrics metrics = new();
		PipelineLogFloodRule rule = new(metrics, new AlertCooldownTracker());
		MockAlertContext context = CreateContext(threshold: 1, enabled: false);

		metrics.IncrementFloodSuppressed();
		Alert? alert = await rule.EvaluateAsync(CreateTriggerEvent(), context, CancellationToken.None);

		Assert.False(rule.IsEnabled(context.Options));
		Assert.Null(alert);
	}

	private static MockAlertContext CreateContext(long threshold, bool enabled = true)
		=> new(new RdpAuditOptions
		{
			Alerts = new AlertOptions
			{
				EnablePipelineFloodDetection = enabled,
				PipelineFloodThreshold = threshold,
				PipelineFloodWindowSeconds = 60,
				ThresholdCooldownMinutes = 15,
			},
		});

	private static RawEvent CreateTriggerEvent()
		=> new()
		{
			Id = 1,
			EventId = 4688,
			Channel = "Security",
			TimeUtc = DateTime.UtcNow,
		};

	private static void IncrementOverflows(ServiceMetrics metrics, int count)
	{
		for (int index = 0; index < count; index++)
		{
			metrics.IncrementRingBufferOverflow();
		}
	}
}
