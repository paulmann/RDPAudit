/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixPageTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Verifies the Zabbix page maps a settings DTO onto its controls, captures edits back into a
//          DTO and renders the status it is given - without a live named pipe. The page must never
//          reach the service directly: the gateway is the only boundary, and a fake proves it.
// Extends: System.Object

using System.Runtime.Versioning;
using System.Windows.Forms;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class ZabbixPageTests
{
	private readonly StaTestHarness _ui = new(nameof(ZabbixPageTests));

	[Fact]
	public void ApplyToControls_MapsEveryEditableField()
	{
		_ui.Run(() =>
		{
			using ZabbixPage page = new(new FakeGateway());
			page.ApplyToControls(new ZabbixSettingsDto
			{
				Enabled = true,
				ServerHost = "22877.ru",
				ServerPort = 10051,
				HostName = "win-bsg-50",
				EffectiveHostName = "win-bsg-50",
				HostGroup = "RDPAudit",
				ApiUrl = "https://22877.ru",
				ApiToken = "***configured***",
				ApiUser = "md",
				ApiPassword = string.Empty,
				ValidateServerCertificate = true,
				TimeoutSeconds = 20,
				PushIntervalSeconds = 120,
				MinimumSeverity = "High",
				MaxIncidentsPerPush = 30,
				MaxBacklogIncidents = 750,
				ProvisionTriggers = true,
				CreateDashboard = false,
				ApiEndpoint = "https://22877.ru/api_jsonrpc.php",
				ProblemsUrl = "https://22877.ru/zabbix.php?action=problem.view",
			});

			ZabbixSettingsDto captured = page.CaptureFromControls();

			Assert.True(captured.Enabled);
			Assert.Equal("22877.ru", captured.ServerHost);
			Assert.Equal(10051, captured.ServerPort);
			Assert.Equal("win-bsg-50", captured.HostName);
			Assert.Equal("https://22877.ru", captured.ApiUrl);
			Assert.Equal("md", captured.ApiUser);
			Assert.Equal(20, captured.TimeoutSeconds);
			Assert.Equal(120, captured.PushIntervalSeconds);
			Assert.Equal("High", captured.MinimumSeverity);
			Assert.Equal(30, captured.MaxIncidentsPerPush);
			Assert.Equal(750, captured.MaxBacklogIncidents);
			Assert.False(captured.CreateDashboard);
		});
	}

	[Fact]
	public void ApplyToControls_ClampsValuesOutsideTheSupportedRange()
	{
		_ui.Run(() =>
		{
			using ZabbixPage page = new(new FakeGateway());
			page.ApplyToControls(new ZabbixSettingsDto
			{
				PushIntervalSeconds = 1,
				TimeoutSeconds = 9_999,
				MaxIncidentsPerPush = 100_000,
				MaxBacklogIncidents = 0,
			});

			ZabbixSettingsDto captured = page.CaptureFromControls();

			Assert.Equal(15, captured.PushIntervalSeconds);
			Assert.Equal(120, captured.TimeoutSeconds);
			Assert.Equal(200, captured.MaxIncidentsPerPush);
			Assert.Equal(1, captured.MaxBacklogIncidents);
		});
	}

	[Fact]
	public void SaveAsync_SendsTheEditedSettingsThroughTheGateway()
	{
		FakeGateway gateway = new();
		_ui.Run(() =>
		{
			using ZabbixPage page = new(gateway);
			page.ApplyToControls(new ZabbixSettingsDto { ServerHost = "old-host", HostGroup = "RDPAudit" });
			// Simulate an operator edit: the page marks itself dirty only on a real control change.
			page.ApplyToControls(new ZabbixSettingsDto { ServerHost = "new-host", HostGroup = "RDPAudit" });
			page.MarkDirty();
			_ui.Await(page.SaveAsync(), "SaveAsync");
		});

		Assert.NotNull(gateway.SavedSettings);
		Assert.Equal("new-host", gateway.SavedSettings!.ServerHost);
		Assert.Equal(1, gateway.SaveCalls);
	}

	[Fact]
	public void RefreshAsync_AppliesSettingsAndFillsTheIncidentList()
	{
		FakeGateway gateway = new()
		{
			Settings = new ZabbixSettingsDto { ServerHost = "22877.ru", EffectiveHostName = "win-a" },
			Status = new ZabbixStatusDto
			{
				HostName = "win-a",
				Message = "Push every 60 s to 22877.ru:10051",
				RecentIncidents = new List<ZabbixSentIncidentDto>
				{
					new() { AlertId = 7, RuleId = "BRUTE_FORCE", Severity = "High" },
				},
			},
		};

		_ui.Run(() =>
		{
			using ZabbixPage page = new(gateway);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");
			Assert.Single(page.RecentRows);
			Assert.Equal("BRUTE_FORCE", page.RecentRows[0].RuleId);
			Assert.Contains("Push every 60 s", page.StatusText, StringComparison.Ordinal);
		});
	}

	[Fact]
	public void RefreshAsync_WhenTheServiceIsUnreachable_ReportsItAndKeepsThePageUsable()
	{
		FakeGateway gateway = new() { Fail = true };

		_ui.Run(() =>
		{
			using ZabbixPage page = new(gateway);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");
			Assert.Contains("Could not load Zabbix settings", page.StatusText, StringComparison.Ordinal);
		});
	}

	private sealed class FakeGateway : IZabbixGateway
	{
		public ZabbixSettingsDto Settings { get; set; } = new();

		public ZabbixStatusDto Status { get; set; } = new();

		public bool Fail { get; set; }

		public ZabbixSettingsDto? SavedSettings { get; private set; }

		public int SaveCalls { get; private set; }

		public Task<IpcCallResult<ZabbixSettingsDto>> GetSettingsAsync(CancellationToken ct = default)
			=> Task.FromResult(Result(IpcCommand.GetZabbixSettings, Fail ? default : Settings, Fail));

		public Task<IpcCallResult<ZabbixSettingsDto>> SaveSettingsAsync(ZabbixSettingsDto dto, CancellationToken ct = default)
		{
			SaveCalls++;
			SavedSettings = dto;
			return Task.FromResult(Result(IpcCommand.SaveZabbixSettings, dto, fail: false));
		}

		public Task<IpcCallResult<ZabbixStatusDto>> GetStatusAsync(CancellationToken ct = default)
			=> Task.FromResult(Result(IpcCommand.GetZabbixStatus, Fail ? default : Status, Fail));

		public Task<IpcCallResult<ZabbixTestResultDto>> TestAsync(CancellationToken ct = default)
			=> Task.FromResult(Result(IpcCommand.TestZabbixConnection, new ZabbixTestResultDto { SenderReachable = true }, fail: false));

		public Task<IpcCallResult<ZabbixPushResultDto>> PushNowAsync(CancellationToken ct = default)
			=> Task.FromResult(Result(IpcCommand.PushZabbixNow, new ZabbixPushResultDto { Delivered = true }, fail: false));

		public Task<IpcCallResult<ZabbixProvisionResultDto>> ProvisionAsync(CancellationToken ct = default)
			=> Task.FromResult(Result(
				IpcCommand.ProvisionZabbix,
				new ZabbixProvisionResultDto { HostCreated = true, ProblemsUrl = "https://zabbix.example/zabbix.php" },
				fail: false));

		private static IpcCallResult<T> Result<T>(IpcCommand command, T? value, bool fail)
			=> fail
				? new IpcCallResult<T>(command, IpcCallOutcome.ConnectFailed, default, "service unreachable", "TimeoutException", DateTime.UtcNow, 5, 5_000, false, false)
				: new IpcCallResult<T>(command, IpcCallOutcome.Success, value, null, null, DateTime.UtcNow, 5, 5_000, true, true);
	}
}
