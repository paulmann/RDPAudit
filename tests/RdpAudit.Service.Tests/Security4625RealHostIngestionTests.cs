// File:    tests/RdpAudit.Service.Tests/Security4625RealHostIngestionTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.0 real-host integration test. The user-reported brute-force evidence on a real
//          Windows host showed Security 4625 with users `md`, `ыва`, `sdf`, IP 77.37.192.246,
//          LogonType 3, signed-decimal Status -1073741715, SubStatus -1073741718 / -1073741724.
//          RawEvents=393 AuthAttemptFacts=0 was the symptom. This test replays exactly that
//          shape end-to-end (Normalize → AuthAttemptFactUpserter → AttackStatsRefreshWorker) and
//          pins the outcome: failed AuthAttemptFact rows are created immediately, with IP, user,
//          LogonType, canonicalised NTSTATUS, and Attack Statistics shows Failed > 0 with
//          First/Last fact populated for 77.37.192.246.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class Security4625RealHostIngestionTests
{
	private const string AttackerIp = "77.37.192.246";
	// Anchor all seeded timestamps two days in the past so every fact stays inside the
	// AttackStatsRefreshWorker 30-day look-back window (DateTime.UtcNow - 30d) while remaining
	// strictly in the past. A fixed calendar date would silently expire 30 days after it was
	// written, which is exactly the regression this constant prevents. Captured once at class
	// load to guarantee a stable value across all reads within a single test run.
	private static readonly DateTime Now = DateTime.UtcNow.AddDays(-2).Date.AddHours(12);

	private static async Task<(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;
		await using (AuditDbContext db = new(options))
		{
			await db.Database.EnsureCreatedAsync();
		}

		return (new TestFactory(options), conn);
	}

	private static string Build4625RealHost(
		string user,
		string ip = AttackerIp,
		string logonType = "3",
		string statusSignedDecimal = "-1073741715",     // 0xC000006D STATUS_LOGON_FAILURE
		string subStatusSignedDecimal = "-1073741718")  // 0xC000006A STATUS_WRONG_PASSWORD
	{
		return $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			$"<System><EventID>4625</EventID></System>" +
			$"<EventData>" +
			$"<Data Name='TargetUserName'>{SecurityElement.Escape(user)}</Data>" +
			$"<Data Name='TargetDomainName'>WORKGROUP</Data>" +
			$"<Data Name='IpAddress'>{ip}</Data>" +
			$"<Data Name='IpPort'>59123</Data>" +
			$"<Data Name='LogonType'>{logonType}</Data>" +
			$"<Data Name='Status'>{statusSignedDecimal}</Data>" +
			$"<Data Name='SubStatus'>{subStatusSignedDecimal}</Data>" +
			$"<Data Name='WorkstationName'>ATTACKER01</Data>" +
			$"<Data Name='AuthenticationPackageName'>NTLM</Data>" +
			$"</EventData></Event>";
	}

	[Fact]
	public void Normalize_4625_RealHostShape_ExtractsAllFields_AndCanonicalisesNtStatus()
	{
		EventNormalizer normalizer = new(new SessionCorrelationCache());
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = "Security",
			TimeUtc = Now,
			XmlPayload = Build4625RealHost("md"),
		});

		Assert.Equal("md", evt.UserName);
		Assert.Equal(AttackerIp, evt.SourceIp);
		Assert.Equal(3, evt.LogonType);
		// Signed decimal -1073741715 canonicalises to 0xC000006D (STATUS_LOGON_FAILURE).
		Assert.Equal("0xC000006D", evt.Status);
		Assert.False(evt.SourceIpUnresolved);
	}

	[Fact]
	public async Task EndToEnd_4625_From77_37_192_246_CreatesFailedFactImmediately()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			EventNormalizer normalizer = new(new SessionCorrelationCache());
			RdpTransportIpCache cache = new();
			AuthAttemptFactUpserter upserter = new(cache);

			string[] users = { "md", "ыва", "sdf" };
			List<RawEvent> entities = new();
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				for (int i = 0; i < users.Length; i++)
				{
					RawEvent re = normalizer.Normalize(new RawEventDto
					{
						EventId = 4625,
						Channel = "Security",
						TimeUtc = Now.AddSeconds(i),
						XmlPayload = Build4625RealHost(users[i]),
					});
					db.RawEvents.Add(re);
					entities.Add(re);
				}

				await db.SaveChangesAsync();

				AuthAttemptFactBatchResult result = await upserter.ApplyAsync(db, entities, CancellationToken.None);
				await db.SaveChangesAsync();
				Assert.Equal(3, result.FailedCreated);
				Assert.Equal(0, result.SucceededCreated);
			}

			await using (AuditDbContext verify = factory.CreateDbContext())
			{
				List<AuthAttemptFact> facts = await verify.AuthAttemptFacts.AsNoTracking().ToListAsync();
				Assert.Equal(3, facts.Count);
				Assert.All(facts, f =>
				{
					Assert.Equal(AttackerIp, f.SourceIp);
					Assert.Equal(AuthAttemptOutcome.Failed, f.Outcome);
					Assert.Equal(3, f.LogonType);
					Assert.Equal("0xC000006D", f.Status);
				});

				Assert.Contains(facts, f => f.TargetUser == "md");
				Assert.Contains(facts, f => f.TargetUser == "ыва");
				Assert.Contains(facts, f => f.TargetUser == "sdf");
			}
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AttackStats_From4625Facts_For77_37_192_246_HasFailedGtZero_AndFirstLastPopulated()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			EventNormalizer normalizer = new(new SessionCorrelationCache());
			RdpTransportIpCache cache = new();
			AuthAttemptFactUpserter upserter = new(cache);

			await using (AuditDbContext db = factory.CreateDbContext())
			{
				List<RawEvent> entities = new();
				string[] users = { "md", "ыва", "sdf", "Administrator" };
				for (int i = 0; i < users.Length; i++)
				{
					RawEvent re = normalizer.Normalize(new RawEventDto
					{
						EventId = 4625,
						Channel = "Security",
						TimeUtc = Now.AddSeconds(i * 5),
						XmlPayload = Build4625RealHost(users[i]),
					});
					db.RawEvents.Add(re);
					entities.Add(re);
				}

				await db.SaveChangesAsync();
				await upserter.ApplyAsync(db, entities, CancellationToken.None);
				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat? stat = await verify.AttackStats.AsNoTracking().FirstOrDefaultAsync(s => s.Ip == AttackerIp);
			Assert.NotNull(stat);
			Assert.True(stat!.Failed > 0, "AttackStat.Failed must be > 0 after 4625 facts for the attacker IP.");
			Assert.Equal(0, stat.Successful);
			Assert.NotEqual(default(DateTime), stat.FirstSeenUtc);
			Assert.NotEqual(default(DateTime), stat.LastSeenUtc);
			Assert.True(stat.LastSeenUtc >= stat.FirstSeenUtc);

			// Attempted usernames are surfaced in Top10AttemptedLogins JSON — verify at least one
			// of the user-reported names round-trips through the projection.
			Assert.Contains("md", stat.Top10AttemptedLogins, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	private sealed class TestFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestFactory(DbContextOptions<AuditDbContext> options)
		{
			_options = options;
		}

		public AuditDbContext CreateDbContext() => new(_options);
	}
}
