// File:    tests/RdpAudit.Notifier.Tests/ToastBudgetTests.cs
// Module:  RdpAudit.Notifier.Tests
// Purpose: Locks the sliding-window rate limiter: cap enforcement, window expiry, clamp.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Notifier.Notifications;
using Xunit;

namespace RdpAudit.Notifier.Tests;

/// <summary>Pins ToastBudget behaviour.</summary>
public class ToastBudgetTests
{
	private sealed class FakeTimeProvider : TimeProvider
	{
		public FakeTimeProvider(DateTime utcNow) => UtcNow = utcNow;

		public DateTime UtcNow { get; set; }

		public override DateTimeOffset GetUtcNow() => new(UtcNow, TimeSpan.Zero);

		public override long GetTimestamp() => UtcNow.Ticks;

		public override long TimestampFrequency => TimeSpan.TicksPerSecond;
	}

	[Fact]
	public void AdmitsUpToCap_ThenThrottles()
	{
		ToastBudget budget = new(new FakeTimeProvider(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)), maximumToastsPerMinute: 3);
		Assert.True(budget.TryAdmit());
		Assert.True(budget.TryAdmit());
		Assert.True(budget.TryAdmit());
		Assert.False(budget.TryAdmit());
	}

	[Fact]
	public void WindowExpiry_AllowsAdmissionAgain()
	{
		FakeTimeProvider time = new(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
		ToastBudget budget = new(time, maximumToastsPerMinute: 2);
		Assert.True(budget.TryAdmit());
		Assert.True(budget.TryAdmit());
		Assert.False(budget.TryAdmit());

		time.UtcNow = time.UtcNow.AddSeconds(61);
		Assert.True(budget.TryAdmit());
	}

	[Fact]
	public void Cap_IsClampedToAtLeastOne()
	{
		ToastBudget budget = new(new FakeTimeProvider(new DateTime(2026, 1, 1)), maximumToastsPerMinute: 0);
		Assert.Equal(1, budget.MaximumToastsPerMinute);
		Assert.True(budget.TryAdmit());
		Assert.False(budget.TryAdmit());
	}
}
