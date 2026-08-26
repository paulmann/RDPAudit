/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : PrivilegedLoginRuleTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Alerts)
// Purpose: Pins the hardened PRIVILEGED_LOGIN rule. Covers the 2026-08-24 start-of-service
//          well-known-SID storm (S-1-5-18/19/20, missing IP), the network-context requirement
//          (source IP + LogonType 3/7/10), the keyed suppression window with a single summary
//          alert on expiry, the per-minute alert budget boundary, the historical/backfill age
//          gate, and a zero-allocation assertion over 10 000 rejection-path EvaluateAsync calls.
// Depends: xUnit, PrivilegedLoginRule, MockAlertContext, System.Text.Json
// Extends: Add a test whenever a new gate or tunable is introduced in PrivilegedLoginRule.

using System.Text.Json;
using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using RdpAudit.Service.Alerts;
using Xunit;

namespace RdpAudit.Service.Tests.Alerts;

public sealed class PrivilegedLoginRuleTests
{
	// ── Fixture helpers ────────────────────────────────────────────────────────

	private static RawEvent PrivilegedEvent(
		string? ip = "203.0.113.10",
		string? user = "alice",
		int? logonType = 10,
		string? sid = null,
		string privilege = "SeDebugPrivilege SeImpersonatePrivilege",
		string? logonId = null,
		DateTime? timeUtc = null) =>
		new()
		{
			Id = 42,
			EventId = 4672,
			Channel = "Security",
			TimeUtc = timeUtc ?? DateTime.UtcNow,
			SourceIp = ip,
			UserName = user,
			LogonType = logonType,
			LogonId = logonId,
			Details = BuildDetails(privilege, sid),
		};

	private static string BuildDetails(string privilege, string? sid)
		=> sid is null
			? "{\"privilegeList\":\"" + privilege + "\"}"
			: "{\"privilegeList\":\"" + privilege + "\",\"subjectUserSid\":\"" + sid + "\"}";

	// ── Well-known service SID filter ──────────────────────────────────────────

	[Theory]
	[InlineData("S-1-5-18")]
	[InlineData("S-1-5-19")]
	[InlineData("S-1-5-20")]
	public async Task WellKnownServiceSid_NoAlert(string sid)
	{
		var rule = new PrivilegedLoginRule();
		var ctx = new MockAlertContext();
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "SYSTEM", logonType: 10, sid: sid);

		Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.Null(alert);
	}

	[Fact]
	public async Task WellKnownServiceSid_NullSid_FailsOpenAndAlerts()
	{
		var rule = new PrivilegedLoginRule();
		var ctx = new MockAlertContext();
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "alice", logonType: 10, sid: null);

		Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.NotNull(alert);
	}

	// ── Network context gate ───────────────────────────────────────────────────

	[Fact]
	public async Task MissingSourceIp_NoAlert()
	{
		var rule = new PrivilegedLoginRule();
		var ctx = new MockAlertContext();
		RawEvent evt = PrivilegedEvent(ip: null, user: "SYSTEM", logonType: 10, sid: null);

		Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.Null(alert);
	}

	[Fact]
	public async Task NonNetworkLogonType5_NoAlert()
	{
		var rule = new PrivilegedLoginRule();
		var ctx = new MockAlertContext();
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "svc-backup", logonType: 5, sid: "S-1-5-21-1000");

		Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.Null(alert);
	}

	[Fact]
	public async Task LogonType10_WithValidIp_Alerts()
	{
		var rule = new PrivilegedLoginRule();
		var ctx = new MockAlertContext();
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "admin", logonType: 10, sid: "S-1-5-21-1000");

		Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.NotNull(alert);
		Assert.Equal("PRIVILEGED_LOGIN", alert!.RuleId);
		Assert.Equal("admin", alert.UserName);
		Assert.Equal("203.0.113.10", alert.SourceIp);
	}

	[Fact]
	public async Task MissingLogonType_Correlated4624LogonType10_Alerts()
	{
		DateTime now = DateTime.UtcNow;
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "admin", logonType: null, sid: "S-1-5-21-1000", logonId: "0x1A2B", timeUtc: now);
		RawEvent logon4624 = new()
		{
			Id = 1,
			EventId = 4624,
			Channel = "Security",
			TimeUtc = now.AddSeconds(-1),
			SourceIp = "203.0.113.10",
			UserName = "admin",
			LogonType = 10,
			LogonId = "0x1A2B",
		};
		var ctx = new MockAlertContext(byUser: new[] { logon4624 });

		Alert? alert = await new PrivilegedLoginRule().EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.NotNull(alert);
	}

	[Fact]
	public async Task MissingLogonType_NoMatching4624_NoAlert()
	{
		DateTime now = DateTime.UtcNow;
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "admin", logonType: null, sid: "S-1-5-21-1000", logonId: "0x1A2B", timeUtc: now);
		var ctx = new MockAlertContext();

		Alert? alert = await new PrivilegedLoginRule().EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.Null(alert);
	}

	// ── Suppression window + summary ───────────────────────────────────────────

	[Fact]
	public async Task SuppressionWindow_FortyIdenticalEvents_OneAlertPlusOneSummary()
	{
		DateTime clock = new(2026, 8, 24, 18, 18, 0, DateTimeKind.Utc);
		var rule = new PrivilegedLoginRule(() => clock);
		var opts = new RdpAuditOptions
		{
			Alerts = new AlertOptions { PrivilegedLoginSuppressionWindowMinutes = 5 },
		};
		var ctx = new MockAlertContext(opts);

		int alerts = 0;
		int suppressed = 0;
		for (int i = 0; i < 40; i++)
		{
			RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "admin", logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
			Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);
			if (alert is null)
			{
				suppressed++;
			}
			else
			{
				alerts++;
			}
		}

		Assert.Equal(1, alerts);
		Assert.Equal(39, suppressed);

		// Window expiry: the first identical event after 5 minutes must produce ONE summary
		// alert carrying the suppressed count, not another ordinary alert.
		clock = clock.AddMinutes(5);
		RawEvent expireTrigger = PrivilegedEvent(ip: "203.0.113.10", user: "admin", logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
		Alert? summary = await rule.EvaluateAsync(expireTrigger, ctx, CancellationToken.None);

		Assert.NotNull(summary);
		Assert.Equal("PRIVILEGED_LOGIN", summary!.RuleId);
		Assert.Contains("39 identical event(s) suppressed", summary.Message, StringComparison.Ordinal);
		using (JsonDocument doc = JsonDocument.Parse(summary.Details!))
		{
			JsonElement root = doc.RootElement;
			Assert.True(root.GetProperty("summary").GetBoolean());
			Assert.Equal(39, root.GetProperty("suppressedCount").GetInt64());
		}

		// The expiry trigger consumes itself as the summary; the following identical event
		// inside the freshly armed window is suppressed again.
		RawEvent next = PrivilegedEvent(ip: "203.0.113.10", user: "admin", logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
		Assert.Null(await rule.EvaluateAsync(next, ctx, CancellationToken.None));
	}

	// ── Historical / backfill gate ─────────────────────────────────────────────

	[Fact]
	public async Task BackfillEvent_OlderThanMaxAge_NoAlert()
	{
		DateTime now = DateTime.UtcNow;
		var rule = new PrivilegedLoginRule(() => now);
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { AlertEventMaxAgeMinutes = 5 } };
		var ctx = new MockAlertContext(opts);
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "admin", logonType: 10, sid: "S-1-5-21-1000", timeUtc: now.AddMinutes(-6));

		Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.Null(alert);
	}

	[Fact]
	public async Task FreshEvent_WithinMaxAge_Alerts()
	{
		DateTime now = DateTime.UtcNow;
		var rule = new PrivilegedLoginRule(() => now);
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { AlertEventMaxAgeMinutes = 5 } };
		var ctx = new MockAlertContext(opts);
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "admin", logonType: 10, sid: "S-1-5-21-1000", timeUtc: now.AddSeconds(-10));

		Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.NotNull(alert);
	}

	// ── Per-minute alert budget boundary ───────────────────────────────────────

	[Fact]
	public async Task RateLimit_AtAndBelowLimit_AllEmit()
	{
		DateTime clock = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
		var rule = new PrivilegedLoginRule(() => clock);
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { PrivilegedLoginRateLimitPerMinute = 3 } };
		var ctx = new MockAlertContext(opts);

		int emitted = 0;
		for (int i = 1; i <= 3; i++)
		{
			RawEvent evt = PrivilegedEvent(ip: "198.51.100." + i, user: "user" + i, logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
			Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);
			if (alert is not null)
			{
				emitted++;
			}
		}

		Assert.Equal(3, emitted); // threshold-1 = 2 and exactly-at-threshold = 3 both emit
	}

	[Fact]
	public async Task RateLimit_BeyondLimit_Throttled()
	{
		DateTime clock = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
		var rule = new PrivilegedLoginRule(() => clock);
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { PrivilegedLoginRateLimitPerMinute = 3 } };
		var ctx = new MockAlertContext(opts);

		for (int i = 1; i <= 3; i++)
		{
			RawEvent evt = PrivilegedEvent(ip: "198.51.100." + i, user: "user" + i, logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
			Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);
			Assert.NotNull(alert);
		}

		RawEvent fourth = PrivilegedEvent(ip: "198.51.100.4", user: "user4", logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
		Alert? throttled = await rule.EvaluateAsync(fourth, ctx, CancellationToken.None);

		Assert.Null(throttled);
	}

	[Fact]
	public async Task RateLimit_NextMinute_ResetsBudget()
	{
		DateTime clock = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
		var rule = new PrivilegedLoginRule(() => clock);
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { PrivilegedLoginRateLimitPerMinute = 3 } };
		var ctx = new MockAlertContext(opts);

		for (int i = 1; i <= 3; i++)
		{
			RawEvent evt = PrivilegedEvent(ip: "198.51.100." + i, user: "user" + i, logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
			await rule.EvaluateAsync(evt, ctx, CancellationToken.None);
		}

		RawEvent fourth = PrivilegedEvent(ip: "198.51.100.4", user: "user4", logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
		Assert.Null(await rule.EvaluateAsync(fourth, ctx, CancellationToken.None));

		clock = clock.AddMinutes(1);
		RawEvent fifth = PrivilegedEvent(ip: "198.51.100.5", user: "user5", logonType: 10, sid: "S-1-5-21-1000", timeUtc: clock);
		Alert? afterReset = await rule.EvaluateAsync(fifth, ctx, CancellationToken.None);

		Assert.NotNull(afterReset);
	}

	// ── Zero-allocation rejection path ──────────────────────────────────────────

	[Fact]
	public async Task RejectionPaths_ZeroAllocation_OverTenThousandCalls()
	{
		DateTime fixedNow = new(2026, 8, 24, 18, 18, 0, DateTimeKind.Utc);
		var rule = new PrivilegedLoginRule(() => fixedNow);
		var opts = new RdpAuditOptions();
		var ctx = new MockAlertContext(opts);
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.50", user: "SYSTEM", logonType: 10, sid: "S-1-5-18", timeUtc: fixedNow);

		// Warm up: FNV bucket lazy-init, JsonOptions static caches, JIT.
		for (int i = 0; i < 1_000; i++)
		{
			await rule.EvaluateAsync(evt, ctx, CancellationToken.None);
		}

		long before = GC.GetAllocatedBytesForCurrentThread();
		for (int i = 0; i < 10_000; i++)
		{
			await rule.EvaluateAsync(evt, ctx, CancellationToken.None);
		}
		long after = GC.GetAllocatedBytesForCurrentThread();

		Assert.Equal(0L, after - before);
	}

	// ── Other contracts ─────────────────────────────────────────────────────────

	[Fact]
	public void RuleId_UnchangedContract()
	{
		Assert.Equal("PRIVILEGED_LOGIN", new PrivilegedLoginRule().RuleId);
	}

	[Fact]
	public async Task NonSensitivePrivileges_NoAlert()
	{
		var rule = new PrivilegedLoginRule();
		var ctx = new MockAlertContext();
		RawEvent evt = PrivilegedEvent(ip: "203.0.113.10", user: "alice", logonType: 10, sid: "S-1-5-21-1000", privilege: "SeChangeNotifyPrivilege");

		Alert? alert = await rule.EvaluateAsync(evt, ctx, CancellationToken.None);

		Assert.Null(alert);
	}

	[Fact]
	public void IsEnabled_FollowsAlertOptions()
	{
		Assert.False(new PrivilegedLoginRule().IsEnabled(
			new RdpAuditOptions { Alerts = new AlertOptions { EnablePrivilegedLoginDetection = false } }));
		Assert.True(new PrivilegedLoginRule().IsEnabled(
			new RdpAuditOptions { Alerts = new AlertOptions { EnablePrivilegedLoginDetection = true } }));
	}
}
