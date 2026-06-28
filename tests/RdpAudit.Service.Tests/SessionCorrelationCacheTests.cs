// File:    tests/RdpAudit.Service.Tests/SessionCorrelationCacheTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Verifies SessionCorrelationCache resolves IPs via LogonId, (SessionId, UserName), and
//          UserName indexes, that TTL expiry skips stale entries, and that capacity-bounded
//          eviction trims the oldest observations first.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SessionCorrelationCacheTests
{
	private sealed class Clock
	{
		public DateTime Now { get; set; } = new DateTime(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc);
		public Func<DateTime> Func => () => Now;
	}

	private static SessionCorrelationCache Build(Clock clock, int capacity = 1024, TimeSpan? ttl = null, TimeSpan? sweep = null)
	{
		return new SessionCorrelationCache(
			capacity,
			ttl ?? TimeSpan.FromHours(24),
			sweep ?? TimeSpan.FromMinutes(5),
			clock.Func);
	}

	[Fact]
	public void Lookup_ByLogonId_ReturnsSeededIp()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock);
		cache.Seed("0x42", sessionId: 1, userName: "alice", ip: "203.0.113.5", utc: clock.Now);

		Assert.Equal("203.0.113.5", cache.Lookup("0x42", sessionId: null, userName: null));
	}

	[Fact]
	public void Lookup_BySessionIdAndUser_ReturnsSeededIp()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock);
		cache.Seed(logonId: null, sessionId: 5, userName: "bob", ip: "198.51.100.7", utc: clock.Now);

		Assert.Equal("198.51.100.7", cache.Lookup(logonId: null, sessionId: 5, userName: "bob"));
	}

	[Fact]
	public void Lookup_UserNameFallback()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock);
		cache.Seed(logonId: null, sessionId: null, userName: "carol", ip: "192.0.2.11", utc: clock.Now);

		Assert.Equal("192.0.2.11", cache.Lookup(logonId: null, sessionId: null, userName: "carol"));
	}

	[Fact]
	public void Lookup_PrefersLogonIdOverUserName()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock);
		// Two events for the same user with different LogonIds.
		cache.Seed("0x100", sessionId: 1, userName: "dave", ip: "10.0.0.1", utc: clock.Now);
		cache.Seed("0x200", sessionId: 2, userName: "dave", ip: "203.0.113.99", utc: clock.Now.AddSeconds(10));

		Assert.Equal("10.0.0.1", cache.Lookup("0x100", sessionId: null, userName: "dave"));
		Assert.Equal("203.0.113.99", cache.Lookup("0x200", sessionId: null, userName: "dave"));
	}

	[Fact]
	public void Lookup_Miss_ReturnsNull()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock);
		Assert.Null(cache.Lookup("0xdead", sessionId: 7, userName: "ghost"));
	}

	[Fact]
	public void Ttl_ExpiredEntry_IsNotReturned()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock, ttl: TimeSpan.FromMinutes(10));
		cache.Seed("0x77", sessionId: null, userName: null, ip: "203.0.113.50", utc: clock.Now);
		clock.Now = clock.Now.AddMinutes(11);

		Assert.Null(cache.Lookup("0x77", sessionId: null, userName: null));
	}

	[Fact]
	public void Seed_NullIp_IsIgnored()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock);
		cache.Seed("0x1", sessionId: 1, userName: "x", ip: string.Empty, utc: clock.Now);
		Assert.Null(cache.Lookup("0x1", null, null));
	}

	[Fact]
	public void Capacity_EvictsOldestEntries()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock, capacity: 100);

		// Seed 250 distinct LogonIds — capacity is 100, so after each overflow ~10% are dropped
		// (the oldest), bringing the index back to ~target. The very first LogonIds must be gone.
		for (int i = 0; i < 250; i++)
		{
			string logon = "0x" + i.ToString("X", CultureInfo.InvariantCulture);
			cache.Seed(logon, sessionId: null, userName: null, ip: $"203.0.113.{i % 250}", utc: clock.Now.AddSeconds(i));
		}

		Assert.Null(cache.Lookup("0x0", null, null));
		// The most recent ones must still be present.
		Assert.NotNull(cache.Lookup("0x" + (249).ToString("X", CultureInfo.InvariantCulture), null, null));
	}

	[Fact]
	public void Logoff_FollowingLogon_GetsDerivedIp()
	{
		Clock clock = new();
		SessionCorrelationCache cache = Build(clock);
		// Simulates 4624 logon followed by 4634 logoff with the same TargetLogonId.
		cache.Seed("0x42", sessionId: null, userName: "alice", ip: "203.0.113.42", utc: clock.Now);
		clock.Now = clock.Now.AddSeconds(5);
		string? derived = cache.Lookup("0x42", sessionId: null, userName: "alice");
		Assert.Equal("203.0.113.42", derived);
	}
}
