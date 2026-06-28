// File:    tests/RdpAudit.Core.Tests/MonitoringConfigRepairTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 2 — ensures stale appsettings.json (pre-v3 config that dropped the Security
//          channel or wrote a partial EnabledEventIds filter) is repaired in place when the
//          service materialises MonitoringOptions. Without this fix the live Security watcher
//          is never armed on upgrade and the Configurator UI reports Failed=0 even when
//          PowerShell can see Security 4625 events.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

public class MonitoringConfigRepairTests
{
	[Fact]
	public void Repair_AddsSecurityChannel_WhenStaleConfigDroppedIt()
	{
		MonitoringOptions opts = new()
		{
			EnabledChannels = new List<string>
			{
				"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
				"System",
			},
			EnabledEventIds = new List<int>(),
		};

		MonitoringConfigRepairReport report = MonitoringConfigRepair.Repair(opts);

		Assert.True(report.Changed);
		Assert.Contains("Security", opts.EnabledChannels);
		Assert.Contains("Security", report.AddedChannels);
		Assert.NotNull(report.Reason);
	}

	[Fact]
	public void Repair_NoChange_WhenSecurityAlreadyPresentAndFilterEmpty()
	{
		MonitoringOptions opts = new()
		{
			EnabledChannels = new List<string> { "Security", "System" },
			EnabledEventIds = new List<int>(),
		};

		MonitoringConfigRepairReport report = MonitoringConfigRepair.Repair(opts);

		Assert.False(report.Changed);
		Assert.Empty(report.AddedChannels);
		Assert.Empty(report.AddedEventIds);
	}

	[Fact]
	public void Repair_AddsRequiredEventIds_WhenFilterIsNonEmptyAndIncomplete()
	{
		MonitoringOptions opts = new()
		{
			EnabledChannels = new List<string> { "Security" },
			EnabledEventIds = new List<int> { 4624, 4688 },
		};

		MonitoringConfigRepairReport report = MonitoringConfigRepair.Repair(opts);

		Assert.True(report.Changed);
		Assert.Empty(report.AddedChannels);
		foreach (int required in MonitoringConfigRepair.RequiredSecurityEventIds)
		{
			Assert.Contains(required, opts.EnabledEventIds);
		}
		// 4688 (process creation) and 4624 (already present) must be preserved.
		Assert.Contains(4688, opts.EnabledEventIds);
		Assert.Contains(4624, opts.EnabledEventIds);
	}

	[Fact]
	public void Repair_LeavesEmptyFilterAlone()
	{
		// An empty EnabledEventIds list semantically means "all events from the catalog for the
		// enabled channels" — we must NOT shrink it down to just the required IDs because that
		// would inadvertently strip every Kerberos / account-management / process-creation event.
		MonitoringOptions opts = new()
		{
			EnabledChannels = new List<string> { "Security" },
			EnabledEventIds = new List<int>(),
		};

		MonitoringConfigRepair.Repair(opts);

		Assert.Empty(opts.EnabledEventIds);
	}

	[Fact]
	public void Repair_IsIdempotent()
	{
		MonitoringOptions opts = new()
		{
			EnabledChannels = new List<string>(),
			EnabledEventIds = new List<int> { 4624 },
		};

		MonitoringConfigRepairReport first = MonitoringConfigRepair.Repair(opts);
		MonitoringConfigRepairReport second = MonitoringConfigRepair.Repair(opts);

		Assert.True(first.Changed);
		Assert.False(second.Changed);
	}

	[Fact]
	public void Repair_HandlesNullEnabledChannelsAndEventIds()
	{
		MonitoringOptions opts = new()
		{
			EnabledChannels = null!,
			EnabledEventIds = null!,
		};

		MonitoringConfigRepairReport report = MonitoringConfigRepair.Repair(opts);

		Assert.NotNull(opts.EnabledChannels);
		Assert.NotNull(opts.EnabledEventIds);
		Assert.True(report.Changed);
		Assert.Contains("Security", opts.EnabledChannels);
	}
}
