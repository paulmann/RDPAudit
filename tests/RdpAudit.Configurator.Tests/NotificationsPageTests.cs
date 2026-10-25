/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : NotificationsPageTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Step 4 verification for the Notifications tab: the page maps NotificationSettingsDto
//          onto controls, applies catalog defaults (alerts shown unless hidden; events shown at
//          High/Critical), clamps numeric values, captures edits back into a DTO and persists
//          them through the settings gateway (commands 78/79 behind INotificationSettingsGateway).
//          Asynchronous page calls run through StaTestHarness, which pumps the STA thread's message
//          queue: blocking the thread that owns the page's WindowsFormsSynchronizationContext would
//          deadlock it against its own ConfigureAwait(true) continuation as soon as a gateway answers
//          asynchronously instead of from a completed Task.
// Depends: NotificationsPage, NotificationCatalogInfo, StaTestHarness, WinForms, xunit
// Extends: when a rule or event enters the catalog, the catalog assertions pick it up automatically.

using System.Runtime.Versioning;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using System.Windows.Forms;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class NotificationsPageTests
{
	/// <summary>Per-class STA host: the message queue is pumped while a test waits for asynchronous page
	/// work, and every wait carries a deadline (see StaTestHarness).</summary>
	private readonly StaTestHarness _ui = new(nameof(NotificationsPageTests));

	[Fact]
	public void SaveAsync_InvokesAutostartService()
	{
		FakeAutostartService autostart = new();
		_ui.Run(() =>
		{
			FakeGateway gateway = new();
			using NotificationsPage page = new(gateway, autostart);
			page.MarkDirty();
			_ui.Await(page.SaveAsync(), "SaveAsync");
		});

		Assert.Equal(1, autostart.ApplyCalls);
		Assert.True(autostart.LastStartWithWindows ?? false);
	}

	private sealed class FakeAutostartService : INotifierAutostartService
	{
		public int ApplyCalls { get; private set; }
		public bool? LastStartWithWindows { get; private set; }

		public Task<NotifierAutostartResult> ApplyAsync(bool startWithWindows)
		{
			ApplyCalls++;
			LastStartWithWindows = startWithWindows;
			return Task.FromResult(new NotifierAutostartResult(true, startWithWindows, "ok"));
		}
	}

	private sealed class FakeGateway : INotificationSettingsGateway
	{
		public NotificationSettingsDto LoadDto { get; set; } = new();
		public bool FailGet { get; set; }
		public NotificationSettingsDto? SavedDto { get; private set; }
		public int GetCalls { get; private set; }
		public int SaveCalls { get; private set; }

		public Task<IpcCallResult<NotificationSettingsDto>> GetAsync(CancellationToken ct = default)
		{
			GetCalls++;
			return Task.FromResult(FailGet
				? Error()
				: Ok(LoadDto, IpcCommand.GetNotificationSettings));
		}

		public Task<IpcCallResult<NotificationSettingsDto>> SaveAsync(NotificationSettingsDto dto, CancellationToken ct = default)
		{
			SaveCalls++;
			SavedDto = dto;
			return Task.FromResult(Ok(dto, IpcCommand.SaveNotificationSettings));
		}

		private static IpcCallResult<NotificationSettingsDto> Ok(NotificationSettingsDto dto, IpcCommand command)
			=> new(command, IpcCallOutcome.Success, dto, null, null, DateTime.UtcNow, 1, 1000, true, true);

		private static IpcCallResult<NotificationSettingsDto> Error()
			=> new(IpcCommand.GetNotificationSettings, IpcCallOutcome.ServiceError, null, "boom", "Test", DateTime.UtcNow, 1, 1000, true, true);
	}

	[Fact]
	public void Catalog_AlertRules_ContainsExactly23UniqueRegisteredRules()
	{
		Assert.Equal(23, NotificationCatalogInfo.AlertRules.Count);
		Assert.Equal(23, NotificationCatalogInfo.AlertRules.Select(r => r.RuleId).Distinct(StringComparer.Ordinal).Count());
	}

	[Fact]
	public void Catalog_AlertRules_SeverityDefaultsMatchKnownRules()
	{
		Assert.Equal(AlertSeverity.High, NotificationCatalogInfo.AlertRules.Single(r => r.RuleId == "BRUTE_FORCE_01").Severity);
		Assert.Equal(AlertSeverity.Critical, NotificationCatalogInfo.AlertRules.Single(r => r.RuleId == "GOLDEN_TICKET").Severity);
		Assert.Equal(AlertSeverity.Low, NotificationCatalogInfo.AlertRules.Single(r => r.RuleId == "OFF_HOURS_LOGIN").Severity);
		Assert.Equal(AlertSeverity.High, NotificationCatalogInfo.AlertRules.Single(r => r.RuleId == "PIPELINE_LOG_FLOOD").Severity);
		Assert.Equal(AlertSeverity.High, NotificationCatalogInfo.AlertRules.Single(r => r.RuleId == "PROCESS_NEW").Severity);
	}

	[Fact]
	public void Catalog_EventVisibility_DefaultMatchesCriticalityThreshold()
	{
		Assert.Contains(EventCatalog.All, d => NotificationCatalogInfo.EventVisibleByDefault(d));
		Assert.Contains(EventCatalog.All, d => !NotificationCatalogInfo.EventVisibleByDefault(d));
	}

	[Fact]
	public void Page_Constructor_ThrowsOnNullGateway()
	{
		_ui.Run(() => Assert.Throws<ArgumentNullException>(() => new NotificationsPage(null!)));
	}

	[Fact]
	public void Page_ApplyToControls_DefaultMaps_BuildsCatalogRows()
	{
		_ui.Run(() =>
		{
			FakeGateway gateway = new();
			using NotificationsPage page = new(gateway);
			page.ApplyToControls(new NotificationSettingsDto());

			Assert.Equal(NotificationCatalogInfo.AlertRules.Count, page.AlertRows.Count);
			Assert.Equal(
				NotificationCatalogInfo.AlertRules.Select(r => r.RuleId),
				page.AlertRows.Select(r => r.RuleId));
			Assert.All(page.AlertRows, row => Assert.True(row.Show));

			Assert.Equal(EventCatalog.All.Count, page.EventRows.Count);
			Assert.Equal(
				EventCatalog.All.Select(d => d.EventId),
				page.EventRows.Select(r => r.EventId));
			for (int i = 0; i < EventCatalog.All.Count; i++)
			{
				bool expected = EventCatalog.All[i].Criticality >= EventCriticality.High;
				Assert.Equal(expected, page.EventRows[i].Show);
			}
		});
	}

	[Fact]
	public void Page_ApplyToControls_ShowAlertsFalseHidesOnlyThatRule()
	{
		_ui.Run(() =>
		{
			using NotificationsPage page = new(new FakeGateway());
			NotificationSettingsDto dto = new();
			dto.ShowAlerts["GOLDEN_TICKET"] = false;
			page.ApplyToControls(dto);

			Assert.False(page.AlertRows.Single(r => r.RuleId == "GOLDEN_TICKET").Show);
			Assert.True(page.AlertRows.Single(r => r.RuleId == "OFF_HOURS_LOGIN").Show);
		});
	}

	[Fact]
	public void Page_ApplyToControls_EventOverrideControlsVisibility()
	{
		_ui.Run(() =>
		{
			using NotificationsPage page = new(new FakeGateway());
			RdpAudit.Core.Events.EventDescriptor low = EventCatalog.All.First(d => d.Criticality < EventCriticality.High);
			RdpAudit.Core.Events.EventDescriptor high = EventCatalog.All.First(d => d.Criticality >= EventCriticality.High);
			NotificationSettingsDto dto = new();
			dto.ShowEvents[NotificationCatalogInfo.EventKey(low.EventId)] = true;
			dto.ShowEvents[NotificationCatalogInfo.EventKey(high.EventId)] = false;
			page.ApplyToControls(dto);

			Assert.True(page.EventRows.Single(r => r.EventId == low.EventId).Show);
			Assert.False(page.EventRows.Single(r => r.EventId == high.EventId).Show);
		});
	}

	[Fact]
	public void Page_ApplyToControls_ClampsOutOfRangeNumbers()
	{
		_ui.Run(() =>
		{
			using NotificationsPage page = new(new FakeGateway());
			NotificationSettingsDto dto = new() { PollIntervalSeconds = 999, MaxToastsPerMinute = 0 };
			page.ApplyToControls(dto);

			NotificationSettingsDto captured = page.CaptureFromControls();
			Assert.Equal(NotificationOptions.MaxPollIntervalSeconds, captured.PollIntervalSeconds);
			Assert.Equal(NotificationOptions.MinMaxToastsPerMinute, captured.MaxToastsPerMinute);
		});
	}

	[Fact]
	public void Page_CaptureFromControls_RoundTripsAppliedSettings()
	{
		_ui.Run(() =>
		{
			using NotificationsPage page = new(new FakeGateway());
			NotificationSettingsDto dto = new()
			{
				EnableTrayNotifier = false,
				StartWithWindows = false,
				UseNativeToasts = true,
				PollIntervalSeconds = 17,
				MaxToastsPerMinute = 3,
				MinimumSeverity = "Critical",
			};
			dto.ShowAlerts["BRUTE_FORCE_01"] = false;
			page.ApplyToControls(dto);

			NotificationSettingsDto captured = page.CaptureFromControls();
			Assert.False(captured.EnableTrayNotifier);
			Assert.False(captured.StartWithWindows);
			Assert.True(captured.UseNativeToasts);
			Assert.Equal(17, captured.PollIntervalSeconds);
			Assert.Equal(3, captured.MaxToastsPerMinute);
			Assert.Equal("Critical", captured.MinimumSeverity);
			Assert.False(captured.ShowAlerts["BRUTE_FORCE_01"]);
			Assert.Equal(NotificationCatalogInfo.AlertRules.Count, captured.ShowAlerts.Count);
			Assert.Equal(EventCatalog.All.Count, captured.ShowEvents.Count);
		});
	}

	[Fact]
	public void Page_RefreshAsync_LoadsSettingsAndReportsStatus()
	{
		_ui.Run(() =>
		{
			FakeGateway gateway = new();
			gateway.LoadDto = new NotificationSettingsDto { PollIntervalSeconds = 42, EnableTrayNotifier = false };
			using NotificationsPage page = new(gateway);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");

			Assert.Equal(1, gateway.GetCalls);
			Assert.Equal(42, page.CaptureFromControls().PollIntervalSeconds);
			Assert.False(page.CaptureFromControls().EnableTrayNotifier);
			Assert.StartsWith("Loaded notification settings at", page.StatusText);
		});
	}

	[Fact]
	public void Page_RefreshAsync_FailureShowsErrorStatus()
	{
		_ui.Run(() =>
		{
			FakeGateway gateway = new() { FailGet = true };
			using NotificationsPage page = new(gateway);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");

			Assert.StartsWith("Could not load notification settings", page.StatusText);
		});
	}

	[Fact]
	public void Page_SaveAsync_PushesSettingsThroughGateway()
	{
		_ui.Run(() =>
		{
			FakeGateway gateway = new();
			using NotificationsPage page = new(gateway);
			page.ApplyToControls(new NotificationSettingsDto());
			page.MarkDirty();
			_ui.Await(page.SaveAsync(), "SaveAsync");

			Assert.Equal(1, gateway.SaveCalls);
			Assert.NotNull(gateway.SavedDto);
			Assert.Equal(NotificationCatalogInfo.AlertRules.Count, gateway.SavedDto!.ShowAlerts.Count);
			Assert.Equal(EventCatalog.All.Count, gateway.SavedDto.ShowEvents.Count);
			Assert.Equal("Notification settings saved.", page.StatusText);
		});
	}

	[Fact]
	public void Page_Layout_HasCompactTopPanelAndDockedTabs()
	{
		_ui.Run(() =>
		{
			using NotificationsPage page = new(new FakeGateway());

			static IEnumerable<Control> AllControls(Control root)
			{
				foreach (Control child in root.Controls)
				{
					yield return child;
					foreach (Control grand in AllControls(child))
					{
						yield return grand;
					}
				}
			}

			Control[] all = AllControls(page).ToArray();

			// The old SplitContainer-based layout is gone.
			Assert.DoesNotContain(all, c => c is SplitContainer);

			TabControl? tabs = all.OfType<TabControl>().SingleOrDefault();
			Assert.NotNull(tabs);
			Assert.Equal(DockStyle.Fill, tabs!.Dock);
			Assert.Equal(2, tabs.TabCount);

			TableLayoutPanel? general = all.OfType<TableLayoutPanel>()
				.SingleOrDefault(p => p.ColumnCount == 2 && p.RowCount == 1);
			Assert.NotNull(general);
			Assert.Equal(DockStyle.Top, general!.Dock);
			Assert.True(general.AutoSize);

			FlowLayoutPanel? checks = all.OfType<FlowLayoutPanel>().SingleOrDefault();
			Assert.NotNull(checks);
			Assert.True(checks!.WrapContents);
			Assert.Equal(FlowDirection.LeftToRight, checks.FlowDirection);

			CheckBox[] checkBoxes = all.OfType<CheckBox>().ToArray();
			Assert.Equal(3, checkBoxes.Length);
			Assert.All(checkBoxes, cb => Assert.True(cb.AutoSize));
		});
	}
}
