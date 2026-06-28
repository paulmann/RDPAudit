// File:    tests/RdpAudit.Service.Tests/EventNormalizerStage3SecurityFieldsTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage 3 — pins the contract that the Security 4625 normalizer extracts user, IP,
//          logon type, status, sub-status, process, port, workstation, auth package and logon
//          process from the NAMED EventData fields (not Properties[N] index) and canonicalises
//          NTSTATUS into 0xXXXXXXXX regardless of whether Windows wrote it as signed-decimal,
//          unsigned-decimal, or hex. Includes the user-reported real-host usernames `md`, the
//          Cyrillic `ыва`, `sdf`, plus a long username and a SQL-injection-shaped username so
//          we never regress to a raw-SQL execution path or crash on hostile input.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Security;
using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventNormalizerStage3SecurityFieldsTests
{
	private const string SecurityChannel = "Security";

	private static EventNormalizer NewNormalizer()
	{
		return new EventNormalizer(new SessionCorrelationCache());
	}

	private static string Build4625(
		string targetUser,
		string ipAddress = "77.37.192.246",
		string logonType = "3",
		string status = "-1073741715",
		string subStatus = "-1073741718",
		string ipPort = "59123",
		string processName = "-",
		string workstation = "ATTACKER01",
		string authPackage = "NTLM",
		string logonProcess = "NtLmSsp")
	{
		// EventData elements are XML-escaped so user-controlled values cannot break the document.
		// SQL-injection-shaped usernames are passed through as XML text; downstream we only ever
		// persist them via parameterised EF Core writes — there is no raw SQL path.
		return $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			$"<System><EventID>4625</EventID></System>" +
			$"<EventData>" +
			$"<Data Name='TargetUserName'>{SecurityElement.Escape(targetUser)}</Data>" +
			$"<Data Name='TargetDomainName'>WORKGROUP</Data>" +
			$"<Data Name='IpAddress'>{ipAddress}</Data>" +
			$"<Data Name='IpPort'>{ipPort}</Data>" +
			$"<Data Name='LogonType'>{logonType}</Data>" +
			$"<Data Name='Status'>{status}</Data>" +
			$"<Data Name='SubStatus'>{subStatus}</Data>" +
			$"<Data Name='ProcessName'>{SecurityElement.Escape(processName)}</Data>" +
			$"<Data Name='WorkstationName'>{workstation}</Data>" +
			$"<Data Name='AuthenticationPackageName'>{authPackage}</Data>" +
			$"<Data Name='LogonProcessName'>{logonProcess}</Data>" +
			$"</EventData></Event>";
	}

	[Theory]
	[InlineData("md")]              // user-reported real-host evidence
	[InlineData("sdf")]             // user-reported real-host evidence
	[InlineData("ыва")]             // Cyrillic — must round-trip without mangling
	[InlineData("админ")]           // Cyrillic — administrator-style username
	[InlineData("Administrator")]
	public void Normalize_4625_ExtractsUserNameFromNamedField(string user)
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = Build4625(user),
		});

		Assert.Equal(user, evt.UserName);
		Assert.Equal("77.37.192.246", evt.SourceIp);
		Assert.Equal(3, evt.LogonType);
	}

	[Fact]
	public void Normalize_4625_LongUserName_DoesNotCrashAndPreservesValue()
	{
		string longUser = new('a', 4096);
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = Build4625(longUser),
		});

		Assert.NotNull(evt.UserName);
		Assert.Equal(4096, evt.UserName!.Length);
	}

	[Theory]
	// SQL-injection-shaped usernames must pass through unchanged into the parameterised EF Core
	// write path. No exception, no truncation, no string concatenation into SQL anywhere.
	[InlineData("admin'; DROP TABLE RawEvents;--")]
	[InlineData("' OR 1=1 --")]
	[InlineData("<script>alert(1)</script>")]
	public void Normalize_4625_HostileUserName_DoesNotCrash(string user)
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = Build4625(user),
		});

		Assert.Equal(user, evt.UserName);
	}

	[Theory]
	// Real-host evidence: Status and SubStatus rendered as signed-decimal int32 must canonicalise
	// into 0xXXXXXXXX before persistence so SubStatusCatalog lookups and SQL predicates align.
	[InlineData("-1073741715", "0xC000006D")] // Misc. Logon Failure
	[InlineData("-1073741718", "0xC000006A")] // Bad Password
	[InlineData("-1073741724", "0xC0000064")] // No Such User
	[InlineData("3221225578", "0xC000006A")]  // unsigned-decimal form
	[InlineData("0xC000006A", "0xC000006A")]  // already canonical
	public void Normalize_4625_CanonicalisesStatusField(string statusRaw, string canonical)
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = Build4625("md", status: statusRaw),
		});

		Assert.Equal(canonical, evt.Status);
	}

	[Fact]
	public void Normalize_4625_CanonicalisesSubStatus_InsideDetailsJson()
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = Build4625("md", subStatus: "-1073741718"),
		});

		Assert.NotNull(evt.Details);
		using JsonDocument doc = JsonDocument.Parse(evt.Details!);
		Assert.True(doc.RootElement.TryGetProperty("SubStatus", out JsonElement sub));
		Assert.Equal("0xC000006A", sub.GetString());
	}

	[Fact]
	public void Normalize_4625_LogonProcessAndAuthPackage_Captured()
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = Build4625("md"),
		});

		Assert.Equal("NTLM", evt.AuthPackage);
		// LogonProcessName is captured into Details since RawEvent does not have a dedicated column.
		Assert.NotNull(evt.Details);
		using JsonDocument doc = JsonDocument.Parse(evt.Details!);
		Assert.True(doc.RootElement.TryGetProperty("LogonProcessName", out JsonElement lp));
		Assert.Equal("NtLmSsp", lp.GetString());
	}
}
