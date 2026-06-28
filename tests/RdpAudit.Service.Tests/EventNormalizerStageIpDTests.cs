// File:    tests/RdpAudit.Service.Tests/EventNormalizerStageIpDTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage IP-D coverage for the TS-RCM 1149 normalization fix. Verifies that Param1
//          (UserName), Param2 (Domain) and Param3 (SourceIp) round-trip cleanly into a RawEvent
//          even though those events use the UserData/EventXML XML schema, and that a 1149-only
//          observation populates SessionCorrelationCache + drives RdpConnectionFact creation
//          via RdpConnectionFactUpserter.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventNormalizerStageIpDTests
{
	private const string TsRcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

	private static string UserData(string eventId, params (string Name, string Value)[] fields)
	{
		string body = string.Join(string.Empty, Array.ConvertAll(fields,
			f => $"<{f.Name}>{f.Value}</{f.Name}>"));
		return $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID></System><UserData><EventXML>{body}</EventXML></UserData></Event>";
	}

	[Fact]
	public void TsRcm_1149_PopulatesUserNameFromParam1()
	{
		EventNormalizer normalizer = new(new SessionCorrelationCache());
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 1149,
			Channel = TsRcmChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = UserData("1149",
				("Param1", "frank"),
				("Param2", "CONTOSO"),
				("Param3", "198.51.100.9")),
		});

		Assert.Equal("frank", evt.UserName);
		Assert.Equal("CONTOSO", evt.Domain);
		Assert.Equal("198.51.100.9", evt.SourceIp);
		Assert.False(evt.SourceIpDerived);
	}

	[Fact]
	public void TsRcm_1149_LeavesDomainNullWhenParam2Blank()
	{
		EventNormalizer normalizer = new(new SessionCorrelationCache());
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 1149,
			Channel = TsRcmChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = UserData("1149",
				("Param1", "alice"),
				("Param2", string.Empty),
				("Param3", "203.0.113.5")),
		});

		Assert.Equal("alice", evt.UserName);
		Assert.Null(evt.Domain);
		Assert.Equal("203.0.113.5", evt.SourceIp);
	}

	[Fact]
	public void TsRcm_1149_StandardFieldsTakePrecedenceOverParam1()
	{
		// If a future event ever ships both TargetUserName and Param1, the standard field wins —
		// our fix is a fallback, not an override.
		EventNormalizer normalizer = new(new SessionCorrelationCache());

		string xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			"<System><EventID>1149</EventID></System>" +
			"<UserData><EventXML><Param1>fromParam1</Param1><Param2>WORKGROUP</Param2><Param3>192.0.2.5</Param3></EventXML></UserData>" +
			"<EventData><Data Name='TargetUserName'>fromEventData</Data></EventData>" +
			"</Event>";

		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 1149,
			Channel = TsRcmChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = xml,
		});

		Assert.Equal("fromEventData", evt.UserName);
	}

	[Fact]
	public void TsRcm_1149_Param1InvalidIp_StillNormalizesUser()
	{
		EventNormalizer normalizer = new(new SessionCorrelationCache());
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 1149,
			Channel = TsRcmChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = UserData("1149",
				("Param1", "carol"),
				("Param2", "ACME"),
				("Param3", "not-an-ip")),
		});

		Assert.Equal("carol", evt.UserName);
		Assert.Equal("ACME", evt.Domain);
		Assert.Null(evt.SourceIp);
	}

	[Fact]
	public void TsRcm_1149_DetailsJsonIncludesParam1Through3()
	{
		EventNormalizer normalizer = new(new SessionCorrelationCache());
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 1149,
			Channel = TsRcmChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = UserData("1149",
				("Param1", "dave"),
				("Param2", "ACME"),
				("Param3", "203.0.113.99")),
		});

		Assert.Contains("dave", evt.Details);
		Assert.Contains("ACME", evt.Details);
		Assert.Contains("203.0.113.99", evt.Details);
	}

	[Fact]
	public async Task TsRcm_1149_CreatesConnectionFactAfterNormalization()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		try
		{
			DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
				.UseSqlite(conn)
				.Options;

			await using (AuditDbContext init = new(options))
			{
				await init.Database.EnsureCreatedAsync();
			}

			EventNormalizer normalizer = new(new SessionCorrelationCache());
			RawEvent evt = normalizer.Normalize(new RawEventDto
			{
				EventId = 1149,
				Channel = TsRcmChannel,
				TimeUtc = new DateTime(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc),
				XmlPayload = UserData("1149",
					("Param1", "ericka"),
					("Param2", "WORKGROUP"),
					("Param3", "203.0.113.42")),
			});

			RdpConnectionFactUpserter upserter = new();
			await using (AuditDbContext db = new(options))
			{
				await upserter.ApplyAsync(db, new[] { evt }, CancellationToken.None);
				await db.SaveChangesAsync();
			}

			await using AuditDbContext check = new(options);
			RdpConnectionFact? row = await check.RdpConnectionFacts
				.FirstOrDefaultAsync(r => r.Ip == "203.0.113.42");
			Assert.NotNull(row);
			Assert.Equal("ericka", row!.UserName);
			Assert.True(row.IsActive);
			Assert.Contains("1149", row.ObservedEventIds ?? string.Empty);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
