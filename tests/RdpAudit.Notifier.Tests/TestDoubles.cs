// Test doubles for the toast routing tests.
using RdpAudit.Core.Models;
using RdpAudit.Notifier.Notifications;

namespace RdpAudit.Notifier.Tests;

internal sealed class FakeToastRenderer : IToastRenderer
{
	public bool Available { get; set; } = true;
	public bool ShowResult { get; set; } = true;
	public List<long> Shown { get; } = [];
	public List<int> Aggregates { get; } = [];

	public bool IsAvailable => Available;
	public bool Show(Alert alert) { Shown.Add(alert.Id); return ShowResult; }
	public bool ShowAggregate(int n) { Aggregates.Add(n); return ShowResult; }
}

internal sealed class FakeNotificationSink : INotificationSink
{
	public List<long> Shown { get; } = [];
	public List<int> Aggregates { get; } = [];
	public bool PreferNativeToasts { get; set; }

	public bool Show(Alert alert) { Shown.Add(alert.Id); return true; }
	public void ShowAggregate(int n) => Aggregates.Add(n);
}

internal static class AlertFactory
{
	public static Alert Alert(long id)
		=> new() { Id = id, Severity = AlertSeverity.High, RuleId = "R", Message = "m" };
}
