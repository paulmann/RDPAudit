// File:    tests/RdpAudit.Service.Tests/AlertRuleTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests covering the alert rule decision boundaries (threshold / whitelist / wrong id).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using RdpAudit.Service.Alerts;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AlertRuleTests
{
	private static RawEvent Logon(int eventId, string? ip = "1.2.3.4", string? user = "alice", int? logonType = 10, string? authPackage = "Kerberos") =>
		new()
		{
			Id = 42,
			EventId = eventId,
			Channel = "Security",
			TimeUtc = DateTime.UtcNow,
			SourceIp = ip,
			UserName = user,
			LogonType = logonType,
			AuthPackage = authPackage,
			Status = "0xC000006A",
		};

	[Fact]
	public async Task BruteForce_BelowThreshold_ReturnsNull()
	{
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 10 } },
			byIp: Enumerable.Range(0, 5).Select(_ => Logon(4625)));
		Assert.Null(await new BruteForceRule().EvaluateAsync(Logon(4625), ctx, default));
	}

	[Fact]
	public async Task BruteForce_AtThreshold_ReturnsAlert()
	{
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 5 } },
			byIp: Enumerable.Range(0, 5).Select(_ => Logon(4625)));
		Alert? alert = await new BruteForceRule().EvaluateAsync(Logon(4625), ctx, default);
		Assert.NotNull(alert);
		Assert.Equal("BRUTE_FORCE_01", alert!.RuleId);
	}

	[Fact]
	public async Task BruteForce_WhitelistedIp_ReturnsNull()
	{
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 5, WhitelistIps = new() { "1.2.3.4" } } };
		var ctx = new MockAlertContext(opts, byIp: Enumerable.Range(0, 50).Select(_ => Logon(4625)));
		Assert.Null(await new BruteForceRule().EvaluateAsync(Logon(4625), ctx, default));
	}

	[Fact]
	public async Task BruteForce_WrongEventId_ReturnsNull()
	{
		var ctx = new MockAlertContext();
		Assert.Null(await new BruteForceRule().EvaluateAsync(Logon(4624), ctx, default));
	}

	[Fact]
	public async Task PassTheHash_NtlmType3WithoutPriorExplicit_ReturnsAlert()
	{
		RawEvent evt = Logon(4624, logonType: 3, authPackage: "NTLM");
		evt.LogonId = "0xABC";
		var ctx = new MockAlertContext();
		Alert? alert = await new PassTheHashRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task PassTheHash_PrecedingExplicitMatchingLogonId_ReturnsNull()
	{
		RawEvent evt = Logon(4624, logonType: 3, authPackage: "NTLM");
		evt.LogonId = "0xABC";
		var preceding = new[]
		{
			new RawEvent { EventId = 4648, LogonId = "0xABC", UserName = evt.UserName },
		};
		var ctx = new MockAlertContext(byUser: preceding);
		Assert.Null(await new PassTheHashRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task PassTheHash_NonNtlm_ReturnsNull()
	{
		RawEvent evt = Logon(4624, logonType: 3, authPackage: "Kerberos");
		var ctx = new MockAlertContext();
		Assert.Null(await new PassTheHashRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task ExternalRdpLogin_LocalIp_ReturnsNull()
	{
		var ctx = new MockAlertContext();
		Assert.Null(await new ExternalRdpLoginRule().EvaluateAsync(Logon(4624, ip: "10.0.0.1"), ctx, default));
	}

	[Fact]
	public async Task ExternalRdpLogin_PublicIp_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new ExternalRdpLoginRule().EvaluateAsync(Logon(4624, ip: "8.8.8.8"), ctx, default);
		Assert.NotNull(alert);
		Assert.Equal("EXTERNAL_RDP_LOGIN", alert!.RuleId);
	}

	[Fact]
	public async Task GoldenTicket_Rc4OnAesDomain_ReturnsAlert()
	{
		RawEvent evt = Logon(4769);
		evt.Details = "{\"TicketEncryptionType\":\"0x17\",\"ServiceName\":\"krbtgt\"}";
		var ctx = new MockAlertContext(new RdpAuditOptions { Alerts = new AlertOptions { KerberosExpectedEncryptionType = "0x12" } });
		Alert? alert = await new GoldenTicketRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task GoldenTicket_AesTicket_ReturnsNull()
	{
		RawEvent evt = Logon(4769);
		evt.Details = "{\"TicketEncryptionType\":\"0x12\"}";
		var ctx = new MockAlertContext(new RdpAuditOptions { Alerts = new AlertOptions { KerberosExpectedEncryptionType = "0x12" } });
		Assert.Null(await new GoldenTicketRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task RdpSessionHijack_TsconExe_ReturnsAlert()
	{
		RawEvent evt = Logon(4688);
		evt.ProcessName = "C:\\Windows\\System32\\tscon.exe";
		var ctx = new MockAlertContext();
		Alert? alert = await new RdpSessionHijackRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task RdpSessionHijack_NormalProcess_ReturnsNull()
	{
		RawEvent evt = Logon(4688);
		evt.ProcessName = "C:\\Windows\\System32\\notepad.exe";
		var ctx = new MockAlertContext();
		Assert.Null(await new RdpSessionHijackRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task UnknownIpSuccess_PriorFailures_ReturnsAlert()
	{
		var addr = new Address { Ip = "1.2.3.4", FailCount = 10, SuccessCount = 1 };
		var ctx = new MockAlertContext(address: addr);
		Alert? alert = await new UnknownIpSuccessRule().EvaluateAsync(Logon(4624), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task UnknownIpSuccess_NoPriorFailures_ReturnsNull()
	{
		var addr = new Address { Ip = "1.2.3.4", FailCount = 0, SuccessCount = 0 };
		var ctx = new MockAlertContext(address: addr);
		Assert.Null(await new UnknownIpSuccessRule().EvaluateAsync(Logon(4624), ctx, default));
	}

	[Fact]
	public async Task RdpPortChanged_OnRdpRegistry_ReturnsAlert()
	{
		RawEvent evt = Logon(4657);
		evt.ObjectName = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber";
		var ctx = new MockAlertContext();
		Alert? alert = await new RdpPortChangedRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task LsassPplTamper_OnLsaRunAsPpl_ReturnsAlert()
	{
		RawEvent evt = Logon(4657);
		evt.ObjectName = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL";
		var ctx = new MockAlertContext();
		Alert? alert = await new LsassPplTamperRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task StickyKeysBackdoor_IfeoSethc_ReturnsAlert()
	{
		RawEvent evt = Logon(4657);
		evt.ObjectName = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe";
		var ctx = new MockAlertContext();
		Alert? alert = await new StickyKeysBackdoorRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task OffHoursLogin_OutsideBusinessHours_ReturnsAlert()
	{
		// Timezone-stable: explicitly evaluate against UTC. 02:00 UTC is outside 09:00-18:00 UTC.
		RawEvent evt = Logon(4624, logonType: 10);
		evt.TimeUtc = DateTime.SpecifyKind(DateTime.UtcNow.Date.AddHours(2), DateTimeKind.Utc);
		var ctx = new MockAlertContext(new RdpAuditOptions
		{
			Alerts = new AlertOptions
			{
				OffHoursAlertEnabled = true,
				BusinessHoursStart = TimeSpan.FromHours(9),
				BusinessHoursEnd = TimeSpan.FromHours(18),
				OffHoursTimeZoneId = "UTC",
			},
		});
		Alert? alert = await new OffHoursLoginRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task OffHoursLogin_InsideBusinessHours_ReturnsNull()
	{
		RawEvent evt = Logon(4624, logonType: 10);
		evt.TimeUtc = DateTime.SpecifyKind(DateTime.UtcNow.Date.AddHours(12), DateTimeKind.Utc);
		var ctx = new MockAlertContext(new RdpAuditOptions
		{
			Alerts = new AlertOptions
			{
				OffHoursAlertEnabled = true,
				BusinessHoursStart = TimeSpan.FromHours(9),
				BusinessHoursEnd = TimeSpan.FromHours(18),
				OffHoursTimeZoneId = "UTC",
			},
		});
		Assert.Null(await new OffHoursLoginRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task NewAccount_4720_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new NewAccountRule().EvaluateAsync(Logon(4720), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task ServiceInstall_4697_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new ServiceInstallRule().EvaluateAsync(Logon(4697), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task TaskPersistence_4698_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new TaskPersistenceRule().EvaluateAsync(Logon(4698), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task TaskModified_4702_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new TaskModifiedRule().EvaluateAsync(Logon(4702), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task PrivilegedGroupChange_4732AdminsGroup_ReturnsAlert()
	{
		RawEvent evt = Logon(4732);
		evt.Details = "{\"TargetUserName\":\"Administrators\"}";
		var ctx = new MockAlertContext(new RdpAuditOptions
		{
			Alerts = new AlertOptions { PrivilegedGroups = new() { "Administrators" } },
		});
		Alert? alert = await new PrivilegedGroupChangeRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task BruteForceNtlm_BelowThreshold_ReturnsNull()
	{
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { BruteForceNtlmThreshold = 20 } },
			byIp: Enumerable.Range(0, 10).Select(_ => Logon(4776)));
		Assert.Null(await new BruteForceNtlmRule().EvaluateAsync(Logon(4776), ctx, default));
	}

	[Fact]
	public async Task KerberosSpray_AtThreshold_ReturnsAlert()
	{
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { KerberosSprayThreshold = 5, BruteForceWindowMinutes = 5 } },
			byIp: Enumerable.Range(0, 5).Select(_ => Logon(4771)));
		Alert? alert = await new KerberosSprayRule().EvaluateAsync(Logon(4771), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task RapidReconnect_DifferentIpWithinWindow_ReturnsAlert()
	{
		RawEvent reconnect = Logon(25, ip: "9.9.9.9");
		reconnect.SessionId = 7;
		var disconnect = new RawEvent { EventId = 24, SessionId = 7, SourceIp = "1.1.1.1", TimeUtc = DateTime.UtcNow.AddSeconds(-5) };
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { RapidReconnectSeconds = 30 } },
			bySession: new[] { disconnect });
		Alert? alert = await new RapidReconnectRule().EvaluateAsync(reconnect, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task ProcessAnomaly_PowerShellFromSvchost_ReturnsAlert()
	{
		RawEvent evt = Logon(4688);
		evt.ProcessName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
		evt.Details = "{\"ParentProcessName\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\"}";
		var ctx = new MockAlertContext();
		Alert? alert = await new ProcessAnomalyRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task PrivilegedLogin_SeDebugInDetails_ReturnsAlert()
	{
		RawEvent evt = Logon(4672);
		evt.Details = "{\"PrivilegeList\":\"SeDebugPrivilege SeBackupPrivilege\"}";
		var ctx = new MockAlertContext();
		Alert? alert = await new PrivilegedLoginRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task LsassAccess_NonLsassObject_ReturnsNull()
	{
		RawEvent evt = Logon(4656);
		evt.ObjectName = "C:\\Windows\\System32\\notepad.exe";
		evt.AccessMask = "0x10";
		var ctx = new MockAlertContext();
		Assert.Null(await new LsassAccessRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task LsassAccess_SensitiveMaskOnLsass_ReturnsAlert()
	{
		RawEvent evt = Logon(4656);
		evt.ObjectName = "\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe";
		evt.AccessMask = "0x1010";
		evt.Details = "{\"ProcessName\":\"C:\\\\Tools\\\\mimikatz.exe\"}";
		var ctx = new MockAlertContext();
		Alert? alert = await new LsassAccessRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task LsassAccess_HighBitMaskOnLsassWithoutSensitive_ReturnsNull()
	{
		// 0x100000 has none of 0x10/0x20/0x08 sensitive bits set; substring "0x10" used to match it incorrectly.
		RawEvent evt = Logon(4656);
		evt.ObjectName = "\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe";
		evt.AccessMask = "0x100000";
		evt.Details = "{\"ProcessName\":\"C:\\\\Tools\\\\mimikatz.exe\"}";
		var ctx = new MockAlertContext();
		Assert.Null(await new LsassAccessRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task LsassAccess_OnlyVmReadFlag_ReturnsAlert()
	{
		// 0x10 alone is exactly PROCESS_VM_READ — sensitive.
		RawEvent evt = Logon(4656);
		evt.ObjectName = "\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe";
		evt.AccessMask = "0x10";
		evt.Details = "{\"ProcessName\":\"C:\\\\Tools\\\\mimikatz.exe\"}";
		var ctx = new MockAlertContext();
		Alert? alert = await new LsassAccessRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public void LsassAccess_TryParseAccessMask_ParsesHexAndDecimal()
	{
		Assert.True(LsassAccessRule.TryParseAccessMask("0x10", out uint a));
		Assert.Equal(0x10u, a);
		Assert.True(LsassAccessRule.TryParseAccessMask("0x1F0FFF", out uint b));
		Assert.Equal(0x1F0FFFu, b);
		Assert.True(LsassAccessRule.TryParseAccessMask("16", out uint c));
		Assert.Equal(16u, c);
		Assert.False(LsassAccessRule.TryParseAccessMask("", out _));
		Assert.False(LsassAccessRule.TryParseAccessMask("not-a-number", out _));
	}

	[Fact]
	public async Task BruteForce_Cooldown_SecondAlertSuppressed()
	{
		AlertCooldownTracker tracker = new();
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 5, ThresholdCooldownMinutes = 60 } },
			byIp: Enumerable.Range(0, 10).Select(_ => Logon(4625)));

		BruteForceRule rule = new(tracker);
		Alert? first = await rule.EvaluateAsync(Logon(4625), ctx, default);
		Alert? second = await rule.EvaluateAsync(Logon(4625), ctx, default);
		Assert.NotNull(first);
		Assert.Null(second);
	}

	[Fact]
	public void Firewall_BuildBlockArgs_RejectsInvalidIp()
	{
		Assert.Throws<ArgumentException>(() => RdpAudit.Service.Services.FirewallManager.BuildBlockArgs("RdpAudit-Block", "not.an.ip"));
	}

	[Fact]
	public void Firewall_BuildBlockArgs_RejectsInjectionInRuleName()
	{
		Assert.Throws<ArgumentException>(() => RdpAudit.Service.Services.FirewallManager.BuildBlockArgs("\"; del *", "1.2.3.4"));
	}

	[Fact]
	public void Firewall_BuildBlockArgs_ProducesExpectedArguments()
	{
		var args = RdpAudit.Service.Services.FirewallManager.BuildBlockArgs("RdpAudit-Block", "1.2.3.4");
		Assert.Contains("advfirewall", args);
		Assert.Contains("name=RdpAudit-Block-1.2.3.4", args);
		Assert.Contains("dir=in", args);
		Assert.Contains("action=block", args);
		Assert.Contains("remoteip=1.2.3.4", args);
	}

	[Fact]
	public void OffHoursLogin_ResolveTimeZone_FallsBackToUtcOnUnknown()
	{
		var tz = RdpAudit.Service.Alerts.OffHoursLoginRule.ResolveTimeZone("This/Zone/Definitely/Does/Not/Exist");
		Assert.Equal(TimeZoneInfo.Utc.Id, tz.Id);
	}

	[Fact]
	public async Task ProcessAnomaly_CmdFromExplorer_DefaultSuppressesAlert()
	{
		RawEvent evt = Logon(4688);
		evt.ProcessName = "C:\\Windows\\System32\\cmd.exe";
		evt.Details = "{\"ParentProcessName\":\"C:\\\\Windows\\\\explorer.exe\"}";
		var ctx = new MockAlertContext();
		Assert.Null(await new ProcessAnomalyRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task ProcessAnomaly_PowerShellFromExplorer_StillAlerts()
	{
		RawEvent evt = Logon(4688);
		evt.ProcessName = "C:\\Windows\\System32\\powershell.exe";
		evt.Details = "{\"ParentProcessName\":\"C:\\\\Windows\\\\explorer.exe\"}";
		var ctx = new MockAlertContext();
		Alert? alert = await new ProcessAnomalyRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public void EventNormalizer_TruncatesHugeDetails_ProducesValidJson()
	{
		var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
		{
			["ProcessName"] = "C:\\Tools\\mimikatz.exe",
			["Big"] = new string('A', 200_000),
		};
		string json = RdpAudit.Service.Processors.EventNormalizer.SerializeAndCap(map);
		Assert.True(json.Length <= 65_536);
		using JsonDocument doc = JsonDocument.Parse(json);
		// ProcessName must remain accessible to LsassAccess / StickyKeys-like rules.
		Assert.True(doc.RootElement.TryGetProperty("ProcessName", out _));
	}

	[Fact]
	public void AuditPolicy_RequiredRows_AllHaveValidGuids()
	{
		Assert.NotEmpty(RdpAudit.Core.Events.AuditPolicyManager.RequiredRows);
		foreach (var row in RdpAudit.Core.Events.AuditPolicyManager.RequiredRows)
		{
			Assert.True(Guid.TryParse(row.SubcategoryGuid.Trim('{', '}'), out _),
				$"Subcategory {row.Subcategory} GUID is invalid: {row.SubcategoryGuid}");
		}
	}

	[Fact]
	public async Task RapidReconnect_SameIp_NoAlert()
	{
		RawEvent reconnect = Logon(25, ip: "9.9.9.9");
		reconnect.SessionId = 7;
		var disconnect = new RawEvent { EventId = 24, SessionId = 7, SourceIp = "9.9.9.9", TimeUtc = DateTime.UtcNow.AddSeconds(-5) };
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { RapidReconnectSeconds = 30 } },
			bySession: new[] { disconnect });
		Assert.Null(await new RapidReconnectRule().EvaluateAsync(reconnect, ctx, default));
	}

	[Fact]
	public async Task PrivilegedLogin_NoSensitivePrivileges_NoAlert()
	{
		RawEvent evt = Logon(4672);
		evt.Details = "{\"PrivilegeList\":\"SeChangeNotifyPrivilege\"}";
		var ctx = new MockAlertContext();
		Assert.Null(await new PrivilegedLoginRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task TaskPersistence_WrongEvent_NoAlert()
	{
		var ctx = new MockAlertContext();
		Assert.Null(await new TaskPersistenceRule().EvaluateAsync(Logon(4625), ctx, default));
	}

	[Fact]
	public async Task ServiceInstall_WrongEvent_NoAlert()
	{
		var ctx = new MockAlertContext();
		Assert.Null(await new ServiceInstallRule().EvaluateAsync(Logon(4625), ctx, default));
	}

	[Fact]
	public async Task NewAccount_WrongEvent_NoAlert()
	{
		var ctx = new MockAlertContext();
		Assert.Null(await new NewAccountRule().EvaluateAsync(Logon(4625), ctx, default));
	}

	// --- Stage 6 ----------------------------------------------------------------------------

	private static RawEvent UnresolvedFail(string user) =>
		new()
		{
			Id = 100,
			EventId = 4625,
			Channel = "Security",
			TimeUtc = DateTime.UtcNow,
			SourceIp = null,
			SourceIpUnresolved = true,
			UserName = user,
		};

	[Fact]
	public async Task Stage6_BruteForce_UnresolvedIp_PerUserThreshold_Fires()
	{
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 5 } };
		var ctx = new MockAlertContext(
			opts,
			byUser: Enumerable.Range(0, 5).Select(_ => UnresolvedFail("attacker")));
		Alert? alert = await new BruteForceRule().EvaluateAsync(UnresolvedFail("attacker"), ctx, default);
		Assert.NotNull(alert);
		Assert.Equal("BRUTE_FORCE_01", alert!.RuleId);
		Assert.Contains("(unresolved)", alert.Message);
		Assert.Contains("attacker", alert.Message);
	}

	[Fact]
	public async Task Stage6_BruteForce_UnresolvedIp_BelowThreshold_NoAlert()
	{
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 10 } };
		var ctx = new MockAlertContext(
			opts,
			byUser: Enumerable.Range(0, 5).Select(_ => UnresolvedFail("attacker")));
		Assert.Null(await new BruteForceRule().EvaluateAsync(UnresolvedFail("attacker"), ctx, default));
	}

	[Fact]
	public async Task Stage6_BruteForce_UnresolvedIp_OnlyCountsUnresolvedFailures()
	{
		// Resolved failures should NOT be folded into the unresolved per-user counter — they
		// have their own IP-based stream.
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 5 } };
		List<RawEvent> mixed = new()
		{
			Logon(4625, ip: "1.2.3.4", user: "attacker"),
			Logon(4625, ip: "1.2.3.4", user: "attacker"),
			UnresolvedFail("attacker"),
			UnresolvedFail("attacker"),
		};
		var ctx = new MockAlertContext(opts, byUser: mixed);
		Assert.Null(await new BruteForceRule().EvaluateAsync(UnresolvedFail("attacker"), ctx, default));
	}
}
