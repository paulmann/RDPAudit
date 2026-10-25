// File:    tests/RdpAudit.Service.Tests/TestAuthAttemptFactHelper.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Shared seeding helper for tests that need to round-trip the v3 atomic fact contract —
//          for every Security 4624 / 4625 / 4648 RawEvent inserted by a test setup, also create
//          the AuthAttemptFact row the production pipeline would have written. Centralised here so
//          a future refactor of the upserter does not require touching every test fixture.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Tests;

/// <summary>Helpers to keep tests aligned with the v3 "AuthAttemptFact is the source of truth"
/// invariant without duplicating the upserter's logic.</summary>
internal static class TestAuthAttemptFactHelper
{
	/// <summary>Add an AuthAttemptFact for every Security RawEvent that the production pipeline
	/// would have created one for. Idempotent — call after seeding RawEvents but before SaveChanges
	/// on the test DbContext.</summary>
	public static void SynthesizeFactsFromRawEvents(AuditDbContext db)
	{
		ArgumentNullException.ThrowIfNull(db);

		List<RawEvent> snapshot = new(db.RawEvents.Local);
		foreach (RawEvent re in snapshot)
		{
			AuthAttemptFact? fact = TryMakeFact(re);
			if (fact is not null)
			{
				db.AuthAttemptFacts.Add(fact);
			}
		}
	}

	private static AuthAttemptFact? TryMakeFact(RawEvent re)
	{
		if (!string.Equals(re.Channel, "Security", StringComparison.OrdinalIgnoreCase))
		{
			return null;
		}

		AuthAttemptOutcome outcome = re.EventId switch
		{
			4624 => AuthAttemptOutcome.Succeeded,
			4625 => AuthAttemptOutcome.Failed,
			4648 => AuthAttemptOutcome.Succeeded,
			4768 => AuthAttemptOutcome.Succeeded,
			4769 => AuthAttemptOutcome.Succeeded,
			4771 => AuthAttemptOutcome.Failed,
			4776 => AuthAttemptOutcome.Succeeded,
			4825 => AuthAttemptOutcome.Denied,
			_ => AuthAttemptOutcome.Unknown,
		};

		if (outcome == AuthAttemptOutcome.Unknown)
		{
			return null;
		}

		return new AuthAttemptFact
		{
			TimeUtc = re.TimeUtc,
			SourceIp = re.SourceIp,
			TargetUser = re.UserName,
			TargetDomain = re.Domain,
			NormalizedUserName = re.UserName?.ToLowerInvariant(),
			AuthPackage = re.AuthPackage,
			LogonType = re.LogonType,
			LogonId = re.LogonId,
			Outcome = outcome,
			Status = re.Status,
			SubStatus = null,
			SubStatusMeaning = null,
			EvidenceChannel = re.Channel,
			EvidenceEventId = re.EventId,
			IpFromCorrelation = re.SourceIpDerived,
			EnrichmentSource = re.SourceIpDerived ? "LogonIdChain" : "DirectXml",
			EnrichmentConfidence = re.SourceIp is null ? "None" : "High",
			NeedsCorrelation = re.SourceIpUnresolved,
			IngestedUtc = re.TimeUtc,
		};
	}
}
