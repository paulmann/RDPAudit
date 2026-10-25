// File:    tests/RdpAudit.Notifier.Tests/NotificationPollerTests.cs
// Module:  RdpAudit.Notifier.Tests
// Purpose: Locks the polling coordinator contract with a fake alert source:
//          settings fetch, degraded delivery, dedup and the aggregate notice.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Notifier.Ipc;
using RdpAudit.Notifier.Notifications;
using Xunit;

namespace RdpAudit.Notifier.Tests;

/// <summary>Pins NotificationPoller orchestration behaviour.</summary>
public class NotificationPollerTests
{
	private sealed class FakeAlertSource : IAlertSource
	{
		public NotificationSettingsDto? Settings { get; set; }
		public List<Alert> Alerts { get; set; } = [];
		public int SettingsCalls { get; private set; }
		public int AlertCalls { get; private set; }

		public Task<NotificationSettingsDto?> FetchSettingsAsync(CancellationToken ct)
		{
			SettingsCalls++;
			return Task.FromResult(Settings);
		}

		public Task<List<Alert>?> FetchRecentAlertsAsync(CancellationToken ct)
		{
			AlertCalls++;
			return Task.FromResult<List<Alert>?>(Alerts);
		}
	}

	private sealed class RecordingSink : INotificationSink
	{
		public List<long> ShownIds { get; } = [];
		public List<int> Aggregates { get; } = [];
		public bool PreferNativeToasts { get; set; }

		public bool Show(Alert alert)
		{
			ShownIds.Add(alert.Id);
			return true;
		}

		public void ShowAggregate(int throttledCount) => Aggregates.Add(throttledCount);
	}

	private static Alert Alert(long id, AlertSeverity severity = AlertSeverity.High)
		=> new() { Id = id, Severity = severity, RuleId = "RULE", Message = "msg" };

	[Fact]
	public async Task DisabledPolicy_FetchesSettingsButNotAlerts()
	{
		FakeAlertSource source = new() { Settings = new NotificationSettingsDto { EnableTrayNotifier = false } };
		RecordingSink sink = new();
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);

		Assert.Equal(1, source.SettingsCalls);
		Assert.Equal(0, source.AlertCalls);
		Assert.Empty(sink.ShownIds);
	}

	[Fact]
	public async Task UnreachableSettings_KeepsDefaultsAndDelivers()
	{
		FakeAlertSource source = new()
		{
			Settings = null,
			Alerts = [Alert(1, AlertSeverity.Critical)],
		};
		RecordingSink sink = new();
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);

		Assert.Equal([1L], sink.ShownIds);
		Assert.Equal(5, poller.CurrentPollIntervalSeconds);
	}

	[Fact]
	public async Task UnreachableAlerts_DoNotThrow()
	{
		FakeAlertSource source = new() { Settings = new NotificationSettingsDto(), Alerts = null! };
		RecordingSink sink = new();
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);
		await poller.TickAsync(CancellationToken.None);

		Assert.Empty(sink.ShownIds);
	}

	[Fact]
	public async Task SelectedAlerts_AreShownOnceAndNewestFirst()
	{
		FakeAlertSource source = new()
		{
			Settings = new NotificationSettingsDto { MinimumSeverity = "High" },
			Alerts = [
				Alert(1, AlertSeverity.Medium),
				Alert(3, AlertSeverity.Critical),
				Alert(2, AlertSeverity.High),
			],
		};
		RecordingSink sink = new();
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);
		await poller.TickAsync(CancellationToken.None);

		Assert.Equal([3L, 2L], sink.ShownIds);
	}

	[Fact]
	public async Task ToastCap_ShowsAggregateForSurplus()
	{
		FakeAlertSource source = new()
		{
			Settings = new NotificationSettingsDto { MaxToastsPerMinute = 2 },
			Alerts = [Alert(4), Alert(3), Alert(2), Alert(1)],
		};
		RecordingSink sink = new();
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);

		Assert.Equal([4L, 3L], sink.ShownIds);
		Assert.Equal([2], sink.Aggregates);
	}

	[Fact]
	public async Task NativeToastPreference_IsPushedToSinkAfterSettingsResolve()
	{
		FakeAlertSource source = new()
		{
			Settings = new NotificationSettingsDto { UseNativeToasts = true },
		};
		RecordingSink sink = new();
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);

		Assert.True(sink.PreferNativeToasts);
	}

	[Fact]
	public async Task UnreachableSettings_LeaveNativePreferenceUntouched()
	{
		FakeAlertSource source = new() { Settings = null };
		RecordingSink sink = new() { PreferNativeToasts = true };
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);

		Assert.True(sink.PreferNativeToasts);
	}

	[Fact]
	public async Task ReachableSettings_SetLastTickSucceeded()
	{
		FakeAlertSource source = new() { Settings = new NotificationSettingsDto() };
		RecordingSink sink = new();
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);

		Assert.True(poller.LastTickSucceeded);
	}

	[Fact]
	public async Task UnreachableSettings_ClearLastTickSucceeded()
	{
		FakeAlertSource source = new() { Settings = null };
		RecordingSink sink = new();
		NotificationPoller poller = new(source, sink);

		await poller.TickAsync(CancellationToken.None);

		Assert.False(poller.LastTickSucceeded);
	}
}
