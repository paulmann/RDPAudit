/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : IpcDispatcherMaskedSettingsTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Locks the completeness contract of the GetSettings payload: every RdpAuditOptions
//          section must be carried with its real values, otherwise a GetSettings -> SaveSettings
//          round-trip from any Configurator tab resets the omitted sections to their CLR defaults.
//          Also pins that secrets are replaced by the mask placeholder and that an empty secret
//          stays empty.
// Depends: IpcDispatcher.BuildMaskedSettings, RdpAuditOptions, xUnit
// Extends: Add an assertion when a new root option section is introduced.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Service.Ipc;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherMaskedSettingsTests
{
	private const string Mask = "***configured***";

	[Fact]
	public void BuildMaskedSettings_CarriesEverySection_WithRealValues()
	{
		RdpAuditOptions src = new();
		src.Sharding.Enabled = true;
		src.Sharding.ShardCapacityRecords = 2048;
		src.Logs.ViewDepthDays = 42;
		src.CrossHost.Enabled = true;
		src.CrossHost.Hosts.Add(new CrossHostHostOptions { HostName = "AGENT-1", Credential = "envelope" });
		src.Notifications.EnableTrayNotifier = false;
		src.Monitoring.ChannelCapacity = 4096;
		src.Firewall.AutoBlockBruteForce = true;
		src.Storage.EventRetentionDays = 123;
		src.Diagnostics.DebugMode = true;
		src.SessionControl.Enabled = true;
		src.ProcessMonitoring.Enabled = true;
		src.Alerts.EnableBruteForceDetection = true;

		RdpAuditOptions masked = IpcDispatcher.BuildMaskedSettings(src);

		// Every section of RdpAuditOptions must be present; a missing one is the defect this pins.
		Assert.NotNull(masked.Monitoring);
		Assert.NotNull(masked.Alerts);
		Assert.NotNull(masked.Firewall);
		Assert.NotNull(masked.Storage);
		Assert.NotNull(masked.Sharding);
		Assert.NotNull(masked.Diagnostics);
		Assert.NotNull(masked.Logs);
		Assert.NotNull(masked.AbuseIpDb);
		Assert.NotNull(masked.MikroTik);
		Assert.NotNull(masked.Api);
		Assert.NotNull(masked.CrossHost);
		Assert.NotNull(masked.SessionControl);
		Assert.NotNull(masked.ProcessMonitoring);
		Assert.NotNull(masked.Notifications);

		// Real values survive — they were NOT reset to CLR defaults.
		Assert.True(masked.Sharding.Enabled);
		Assert.Equal(2048, masked.Sharding.ShardCapacityRecords);
		Assert.Equal(42, masked.Logs.ViewDepthDays);
		Assert.True(masked.CrossHost.Enabled);
		Assert.Equal("AGENT-1", masked.CrossHost.Hosts[0].HostName);
		Assert.False(masked.Notifications.EnableTrayNotifier);
		Assert.Equal(4096, masked.Monitoring.ChannelCapacity);
		Assert.True(masked.Firewall.AutoBlockBruteForce);
		Assert.Equal(123, masked.Storage.EventRetentionDays);
		Assert.True(masked.Diagnostics.DebugMode);
		Assert.True(masked.SessionControl.Enabled);
		Assert.True(masked.ProcessMonitoring.Enabled);
		Assert.True(masked.Alerts.EnableBruteForceDetection);
	}

	[Fact]
	public void BuildMaskedSettings_MasksEverySecret()
	{
		RdpAuditOptions src = new();
		src.AbuseIpDb.ApiKey = "real-abuse-key";
		src.MikroTik.Password = "real-router-password";
		src.Api.Token = "real-api-token";
		src.CrossHost.Hosts.Add(new CrossHostHostOptions { HostName = "AGENT-1", Credential = "real-envelope" });

		RdpAuditOptions masked = IpcDispatcher.BuildMaskedSettings(src);

		Assert.Equal(Mask, masked.AbuseIpDb.ApiKey);
		Assert.Equal(Mask, masked.MikroTik.Password);
		Assert.Equal(Mask, masked.Api.Token);
		Assert.Equal(Mask, masked.CrossHost.Hosts[0].Credential);

		// The source object is not mutated by masking.
		Assert.Equal("real-abuse-key", src.AbuseIpDb.ApiKey);
		Assert.Equal("real-envelope", src.CrossHost.Hosts[0].Credential);
	}

	[Fact]
	public void BuildMaskedSettings_EmptySecretsStayEmpty()
	{
		RdpAuditOptions masked = IpcDispatcher.BuildMaskedSettings(new RdpAuditOptions());

		Assert.Equal(string.Empty, masked.AbuseIpDb.ApiKey);
		Assert.Equal(string.Empty, masked.MikroTik.Password);
		Assert.Equal(string.Empty, masked.Api.Token);
		Assert.Empty(masked.CrossHost.Hosts);
	}
}
