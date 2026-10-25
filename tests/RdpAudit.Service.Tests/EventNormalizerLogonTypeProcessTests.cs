// File:    tests/RdpAudit.Service.Tests/EventNormalizerLogonTypeProcessTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage FIX-2 — locks the per-event LogonType and Process extraction the LiveEvents tab
//          relies on. Without these tests a regression in EventXmlParser or the normalizer would
//          silently render LogonType / Process as blanks in the LiveEvents grid.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventNormalizerLogonTypeProcessTests
{
	private const string SecurityChannel = "Security";

	private static string EventData(string eventId, params (string Name, string Value)[] fields)
	{
		string body = string.Join(string.Empty, Array.ConvertAll(fields,
			f => $"<Data Name='{f.Name}'>{f.Value}</Data>"));
		return $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID></System><EventData>{body}</EventData></Event>";
	}

	private static EventNormalizer NewNormalizer()
	{
		return new EventNormalizer(new SessionCorrelationCache());
	}

	[Fact]
	public void Security_4624_Populates_LogonType_And_ProcessName()
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4624,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4624",
				("IpAddress", "203.0.113.10"),
				("TargetUserName", "alice"),
				("LogonType", "10"),
				("ProcessName", @"C:\Windows\System32\winlogon.exe")),
		});

		Assert.Equal(10, evt.LogonType);
		Assert.Equal(@"C:\Windows\System32\winlogon.exe", evt.ProcessName);
	}

	[Fact]
	public void Security_4625_Populates_LogonType_For_FailedLogon()
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4625",
				("IpAddress", "198.51.100.20"),
				("TargetUserName", "admin"),
				("LogonType", "3"),
				("Status", "0xC000006D"),
				("FailureReason", "%%2313")),
		});

		Assert.Equal(3, evt.LogonType);
	}

	[Fact]
	public void Security_4688_Populates_ProcessName_FromNewProcessName_And_CommandLine()
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4688,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4688",
				("SubjectUserName", "bob"),
				("NewProcessName", @"C:\Windows\System32\cmd.exe"),
				("CommandLine", @"cmd.exe /c whoami")),
		});

		Assert.Equal(@"C:\Windows\System32\cmd.exe", evt.ProcessName);
		Assert.Equal(@"cmd.exe /c whoami", evt.CommandLine);
	}
}
