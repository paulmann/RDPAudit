/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostFactExporterTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: P4-18 Step 6 unit tests for the agent-side cross-host fact exporter. The exporter is
//          the LOCAL half of GetCrossHostFacts: it reads persisted AuthAttemptFact rows and
//          privileged-logon RawEvent rows, projects them into bounded CrossHostFactDto summaries
//          carrying stable DedupKeys, and never leaks raw event XML.
// Depends: CrossHostFactExporter, AuthAttemptFact, RawEvent, CrossHostFactsRequest/Dto, xUnit
// Extends: Add per-kind coverage whenever a new CrossHostFactKind mapping rule is introduced.

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Config;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Unit tests for the agent-side cross-host fact exporter.</summary>
public sealed class CrossHostFactExporterTests : IDisposable
{
	private readonly AuditDbContext _db;

	public CrossHostFactExporterTests()
	{
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite("DataSource=:memory:")
			.Options;
		_db = new AuditDbContext(options);
		_db.Database.OpenConnection();
		_db.Database.Migrate();
	}

	public void Dispose()
	{
		_db.Database.CloseConnection();
		_db.Dispose();
	}

	// Evaluated per test so the exporter's 24-hour age cutoff stays meaningful regardless of
	// when the suite runs: a frozen timestamp goes stale and silently drops the 4672 facts.
	private static DateTime Now => DateTime.UtcNow;

	private static AuthAttemptFact Fact(
		DateTime timeUtc,
		string user,
		string ip,
		AuthAttemptOutcome outcome,
		int eventId,
		int? logonType)
	{
		string normalized = AuthAttemptFactUpserter.NormalizeUserName(user)!;
		return new AuthAttemptFact
		{
			TimeUtc = timeUtc,
			SourceIp = ip,
			TargetUser = user,
			NormalizedUserName = normalized,
			LogonType = logonType,
			Outcome = outcome,
			EvidenceEventId = eventId,
			EvidenceChannel = "Security",
			IngestedUtc = timeUtc,
		};
	}

	private CrossHostFactExporter CreateExporter()
		=> new(NullLogger<CrossHostFactExporter>.Instance, TimeProvider.System);

	[Fact]
	public async Task ExportAsync_Succeeded4624_ProjectsSuccessfulLogonFact()
	{
		_db.AuthAttemptFacts.Add(Fact(Now.AddMinutes(-5), "DOMAIN\\alice", "198.51.100.10", AuthAttemptOutcome.Succeeded, 4624, 10));
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 }, new CrossHostOptions(), default);

		Assert.Equal(IpcResultStatus.Success, dto.Status);
		CrossHostFactDto fact = Assert.Single(dto.Facts);
		Assert.Equal(CrossHostFactKind.SuccessfulLogon, fact.Kind);
		Assert.Equal(4624, fact.EventId);
		Assert.Equal("DOMAIN\\alice", fact.UserName);
		Assert.Equal("alice", fact.NormalizedUserName);
		Assert.Equal("198.51.100.10", fact.SourceIp);
		Assert.Equal(10, fact.LogonType);
		Assert.False(string.IsNullOrWhiteSpace(fact.DedupKey));
	}

	[Fact]
	public async Task ExportAsync_Failed4625_ProjectsFailedLogonFact()
	{
		_db.AuthAttemptFacts.Add(Fact(Now.AddMinutes(-2), "bob@contoso.local", "203.0.113.7", AuthAttemptOutcome.Failed, 4625, 3));
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 }, new CrossHostOptions(), default);

		CrossHostFactDto fact = Assert.Single(dto.Facts);
		Assert.Equal(CrossHostFactKind.FailedLogon, fact.Kind);
		Assert.Equal(4625, fact.EventId);
		Assert.Equal("bob", fact.NormalizedUserName);
		Assert.False(string.IsNullOrWhiteSpace(fact.DedupKey));
	}

	[Fact]
	public async Task ExportAsync_Denied4625_StillFailedLogonKind()
	{
		_db.AuthAttemptFacts.Add(Fact(Now, "carol", "198.51.100.99", AuthAttemptOutcome.Denied, 4625, 3));
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 }, new CrossHostOptions(), default);

		CrossHostFactDto fact = Assert.Single(dto.Facts);
		Assert.Equal(CrossHostFactKind.FailedLogon, fact.Kind);
	}

	[Fact]
	public async Task ExportAsync_UnknownOutcome_IsSkipped()
	{
		_db.AuthAttemptFacts.Add(Fact(Now, "dave", "203.0.113.1", AuthAttemptOutcome.Unknown, 4624, 3));
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 }, new CrossHostOptions(), default);

		Assert.Empty(dto.Facts);
	}

	[Fact]
	public async Task ExportAsync_NonNetworkLogonType_IsSkipped()
	{
		_db.AuthAttemptFacts.Add(Fact(Now, "eve", "203.0.113.2", AuthAttemptOutcome.Succeeded, 4624, 5));
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 }, new CrossHostOptions(), default);

		Assert.Empty(dto.Facts);
	}

	[Fact]
	public async Task ExportAsync_PrivilegedLogonMerged_Produces4672Fact()
	{
		_db.AuthAttemptFacts.Add(Fact(Now.AddMinutes(-8), "gina" , "198.51.100.5", AuthAttemptOutcome.Succeeded, 4624, 10));
		await _db.SaveChangesAsync();
		_db.RawEvents.Add(new RawEvent
		{
			EventId = 4672,
			Channel = "Security",
			TimeUtc = Now.AddMinutes(-7),
			UserName = "gina",
			SourceIp = "198.51.100.5",
			LogonType = 10,
			Details = "{\"PrivilegeList\":\"SeDebugPrivilege\"}",
		});
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 }, new CrossHostOptions(), default);

		Assert.Equal(2, dto.Facts.Count);
		CrossHostFactDto privileged = Assert.Single(dto.Facts, f => f.EventId == 4672);
		Assert.Equal(CrossHostFactKind.PrivilegedLogon, privileged.Kind);
		Assert.Equal("gina", privileged.NormalizedUserName);
		Assert.Equal("198.51.100.5", privileged.SourceIp);
	}

	[Fact]
	public async Task ExportAsync_PrivilegedLogon_Past24Hours_IsSkipped()
	{
		_db.RawEvents.Add(new RawEvent
		{
			EventId = 4672,
			Channel = "Security",
			TimeUtc = Now.AddHours(-25),
			UserName = "gina",
			SourceIp = "198.51.100.5",
			LogonType = 10,
			Details = "{\"PrivilegeList\":\"SeDebugPrivilege\"}",
		});
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 }, new CrossHostOptions(), default);

		Assert.Empty(dto.Facts);
	}

	[Fact]
	public async Task ExportAsync_SinceUtc_FiltersExclusive()
	{
		_db.AuthAttemptFacts.Add(Fact(Now.AddMinutes(-30), "alice", "198.51.100.10", AuthAttemptOutcome.Failed, 4625, 3));
		_db.AuthAttemptFacts.Add(Fact(Now.AddMinutes(-10), "bob", "198.51.100.11", AuthAttemptOutcome.Failed, 4625, 3));
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = Now.AddMinutes(-20), MaxFacts = 100 }, new CrossHostOptions(), default);

		Assert.Single(dto.Facts);
		Assert.Equal("bob", dto.Facts[0].NormalizedUserName);
	}

	[Fact]
	public async Task ExportAsync_MaxFactsClampedByOptions_And_OrdersAscending()
	{
		for (int i = 1; i <= 5; i++)
		{
			_db.AuthAttemptFacts.Add(Fact(Now.AddMinutes(-i), $"user{i}", $"198.51.100.{i}", AuthAttemptOutcome.Failed, 4625, 3));
		}
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(
			_db,
			new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 },
			new CrossHostOptions { MaxFactsPerPoll = 3 },
			default);

		Assert.Equal(3, dto.Facts.Count);
		for (int i = 1; i < dto.Facts.Count; i++)
		{
			Assert.True(dto.Facts[i].TimeUtc >= dto.Facts[i - 1].TimeUtc, "facts must be ordered TimeUtc ascending");
		}
	}

	[Fact]
	public async Task ExportAsync_LatestFactUtc_IsMaxAndWatermark()
	{
		DateTime now = Now;
		_db.AuthAttemptFacts.Add(Fact(now.AddMinutes(-10), "alice", "198.51.100.10", AuthAttemptOutcome.Failed, 4625, 3));
		_db.AuthAttemptFacts.Add(Fact(now.AddMinutes(-4), "bob", "198.51.100.11", AuthAttemptOutcome.Failed, 4625, 3));
		await _db.SaveChangesAsync();

		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 100 }, new CrossHostOptions(), default);

		Assert.NotNull(dto.LatestFactUtc);
		Assert.Equal(now.AddMinutes(-4), dto.LatestFactUtc!.Value);
	}

	[Fact]
	public async Task ExportAsync_EmptyWindow_ReturnsSuccessNoFacts()
	{
		CrossHostFactsDto dto = await CreateExporter().ExportAsync(_db, new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 10 }, new CrossHostOptions(), default);

		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Empty(dto.Facts);
		Assert.Null(dto.LatestFactUtc);
	}
}
