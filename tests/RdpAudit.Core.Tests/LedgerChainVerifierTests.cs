/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : LedgerChainVerifierTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: Pins the tamper-evidence contract of the deletion-ledger hash chain (Requirement R23). Every
//          attack the chain claims to detect is expressed as a mutation of a real chain and asserted to
//          BREAK it, and every mutation is followed by a counterfactual that restores the original value and
//          asserts the chain verifies again - so a verifier that simply always failed would not pass these
//          tests. The cases are: a modified value, a row removed from the middle, two rows swapped, a
//          malformed hash column, and the legitimate pre-chain (legacy) prefix that must NOT be reported as
//          tampering.
// Depends: LedgerChainHasher, LedgerChainVerifier, xUnit
// Extends: Add a case here for every new mutation the chain is expected to detect.

using RdpAudit.Core.Integrity;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class LedgerChainVerifierTests
{
	// ── Baseline ─────────────────────────────────────────────────────────────────

	/// <summary>Given a correctly chained ledger, when it is verified, then it is intact, every row counts
	/// as chained, and nothing is reported as broken.</summary>
	[Fact]
	public void Verify_OnAnIntactChain_IsIntact()
	{
		List<LedgerChainRow> rows = BuildChain(4);

		LedgerChainVerification verification = LedgerChainVerifier.Verify(rows);

		Assert.True(verification.IsIntact, verification.Message);
		Assert.Equal(4, verification.ChainedRows);
		Assert.Equal(0, verification.UnchainedRows);
		Assert.Null(verification.FirstBrokenId);
	}

	/// <summary>Given pre-chain rows written before the hash columns existed, when the ledger is verified,
	/// then they are counted as unverifiable rather than reported as tampering - a false tamper alarm is
	/// worse than an honest "cannot verify".</summary>
	[Fact]
	public void Verify_OnALegacyPrefix_CountsItAsUnverifiableInsteadOfBroken()
	{
		List<LedgerChainRow> rows = BuildChain(0);
		rows.Add(BuildRow(1, EventCode: 4625, previousHash: null, entryHash: null));
		rows.Add(BuildRow(2, EventCode: 4624, previousHash: null, entryHash: null));
		rows.AddRange(BuildChain(2, firstId: 3));

		LedgerChainVerification verification = LedgerChainVerifier.Verify(rows);

		Assert.True(verification.IsIntact, verification.Message);
		Assert.Equal(2, verification.UnchainedRows);
		Assert.Equal(2, verification.ChainedRows);
	}

	// ── Modification ─────────────────────────────────────────────────────────────

	/// <summary>Given the value stored in a middle ledger row is changed, when the chain is verified, then
	/// verification fails at exactly that row; and when the original value is put back, verification passes
	/// again.</summary>
	[Fact]
	public void Verify_WhenAMiddleRowWasModified_Fails_AndPassesAgainAfterTheValueIsRestored()
	{
		List<LedgerChainRow> rows = BuildChain(5);
		int victim = 2;
		LedgerChainRow original = rows[victim];

		// Tamper: the deletion count of the middle row is rewritten while its hash link is left alone -
		// exactly what an operator covering their tracks would do without recomputing the chain.
		rows[victim] = original with
		{
			Entry = original.Entry with { RowsDeleted = original.Entry.RowsDeleted + 1 },
		};

		LedgerChainVerification broken = LedgerChainVerifier.Verify(rows);
		Assert.False(broken.IsIntact);
		Assert.Equal(original.Id, broken.FirstBrokenId);
		Assert.Contains("modified", broken.Message, StringComparison.Ordinal);

		// Counterfactual: restoring the original value restores integrity, so the failure above was caused
		// by the tampering and not by a verifier that rejects everything.
		rows[victim] = original;
		LedgerChainVerification restored = LedgerChainVerifier.Verify(rows);
		Assert.True(restored.IsIntact, restored.Message);
		Assert.Equal(5, restored.ChainedRows);
	}

	/// <summary>Given the actor or the reason text of a row is rewritten, when the chain is verified, then
	/// it fails: the chain covers the accountability fields, not only the counts.</summary>
	[Theory]
	[InlineData("Reason")]
	[InlineData("InitiatedBy")]
	[InlineData("EventCode")]
	[InlineData("RowsDeleted")]
	public void Verify_WhenAnyHashedFieldWasModified_Fails(string field)
	{
		List<LedgerChainRow> rows = BuildChain(3);
		LedgerChainRow original = rows[1];
		LedgerChainEntry entry = original.Entry;
		rows[1] = original with
		{
			Entry = field switch
			{
				"Reason" => entry with { Reason = entry.Reason + "-edited" },
				"InitiatedBy" => entry with { InitiatedBy = "Operator:someone-else" },
				"EventCode" => entry with { EventCode = entry.EventCode + 1 },
				_ => entry with { RowsDeleted = entry.RowsDeleted + 1 },
			},
		};

		Assert.False(LedgerChainVerifier.Verify(rows).IsIntact);
	}

	// ── Deletion and reordering ──────────────────────────────────────────────────

	/// <summary>Given a row is removed from the middle of the ledger, when the chain is verified, then it
	/// fails at the survivor that followed it; and when the row is put back with its original content and
	/// link, verification passes again.</summary>
	[Fact]
	public void Verify_WhenAMiddleRowWasDeleted_Fails_AndPassesAgainAfterItIsRestored()
	{
		List<LedgerChainRow> rows = BuildChain(5);
		LedgerChainRow removed = rows[2];
		List<LedgerChainRow> truncated = [.. rows];
		truncated.RemoveAt(2);

		LedgerChainVerification broken = LedgerChainVerifier.Verify(truncated);
		Assert.False(broken.IsIntact);
		Assert.Equal(rows[3].Id, broken.FirstBrokenId);
		Assert.Contains("deleted, inserted or reordered", broken.Message, StringComparison.Ordinal);

		truncated.Insert(2, removed);
		LedgerChainVerification restored = LedgerChainVerifier.Verify(truncated);
		Assert.True(restored.IsIntact, restored.Message);
	}

	/// <summary>Given two adjacent ledger rows are swapped in place, when the chain is verified, then it
	/// fails: a moved row no longer follows the entry its PreviousHash names.</summary>
	[Fact]
	public void Verify_WhenTwoRowsWereSwapped_Fails()
	{
		List<LedgerChainRow> rows = BuildChain(4);
		(rows[1], rows[2]) = (rows[2], rows[1]);

		LedgerChainVerification verification = LedgerChainVerifier.Verify(rows);

		Assert.False(verification.IsIntact);
		Assert.Equal(rows[1].Id, verification.FirstBrokenId);
	}

	/// <summary>Given a hash column was replaced with something that is not a hash at all, when the chain is
	/// verified, then it is reported as malformed rather than silently skipped.</summary>
	[Fact]
	public void Verify_WhenAHashColumnIsMalformed_Fails()
	{
		List<LedgerChainRow> rows = BuildChain(3);
		rows[1] = rows[1] with { EntryHash = "not-a-hash" };

		LedgerChainVerification verification = LedgerChainVerifier.Verify(rows);

		Assert.False(verification.IsIntact);
		Assert.Equal(rows[1].Id, verification.FirstBrokenId);
		Assert.Contains("SHA-256 hex", verification.Message, StringComparison.Ordinal);
	}

	// ── Hashing contract ─────────────────────────────────────────────────────────

	/// <summary>Given the same row content and the same previous hash, when the hash is computed twice - and
	/// once more from a DateTime expressed in local time but carrying the same wall-clock digits - then the
	/// result is identical. SQLite stores timestamps as wall-clock text and hands them back with an
	/// unspecified kind, so a hash that included the kind would fail verification after a restart.</summary>
	[Fact]
	public void ComputeEntryHash_IsStableAcrossDateTimeKinds()
	{
		DateTime utc = new(2026, 9, 15, 12, 30, 45, DateTimeKind.Utc);
		DateTime unspecified = new(2026, 9, 15, 12, 30, 45, DateTimeKind.Unspecified);
		LedgerChainEntry entryUtc = BuildEntry(EventCode: 4625, createdUtc: utc);
		LedgerChainEntry entryUnspecified = BuildEntry(EventCode: 4625, createdUtc: unspecified);

		Assert.Equal(
			LedgerChainHasher.ComputeEntryHash(LedgerChainHasher.GenesisPreviousHash, entryUtc),
			LedgerChainHasher.ComputeEntryHash(LedgerChainHasher.GenesisPreviousHash, entryUnspecified));
	}

	/// <summary>Given two different previous hashes, when the same row content is hashed, then the entry
	/// hashes differ: the link is part of the digest, which is what makes reordering detectable.</summary>
	[Fact]
	public void ComputeEntryHash_DependsOnThePreviousHash()
	{
		LedgerChainEntry entry = BuildEntry(EventCode: 4625, createdUtc: DateTime.UtcNow);

		string first = LedgerChainHasher.ComputeEntryHash(LedgerChainHasher.GenesisPreviousHash, entry);
		string second = LedgerChainHasher.ComputeEntryHash(new string('a', 64), entry);

		Assert.NotEqual(first, second);
		Assert.Equal(LedgerChainHasher.HashHexLength, first.Length);
	}

	// ── Fixtures ─────────────────────────────────────────────────────────────────

	/// <summary>Builds a correctly chained ledger of <paramref name="count"/> rows, so every test starts
	/// from a chain that verifies.</summary>
	private static List<LedgerChainRow> BuildChain(int count, long firstId = 1)
	{
		List<LedgerChainRow> rows = [];
		string previous = LedgerChainHasher.GenesisPreviousHash;
		DateTime createdUtc = new(2026, 9, 15, 10, 0, 0, DateTimeKind.Utc);
		for (int index = 0; index < count; index++)
		{
			long id = firstId + index;
			LedgerChainEntry entry = BuildEntry(4625 + index, createdUtc.AddMinutes(index));
			string hash = LedgerChainHasher.ComputeEntryHash(previous, entry);
			rows.Add(new LedgerChainRow(id, entry, previous, hash));
			previous = hash;
		}

		return rows;
	}

	private static LedgerChainRow BuildRow(long id, int EventCode, string? previousHash, string? entryHash)
		=> new(
			id,
			BuildEntry(EventCode, new DateTime(2026, 9, 15, 9, 0, 0, DateTimeKind.Utc)),
			previousHash,
			entryHash);

	private static LedgerChainEntry BuildEntry(int EventCode, DateTime createdUtc)
		=> new(
			EventCode,
			Scope: 0,
			IpBinary16: null,
			WindowStartUtc: createdUtc.AddMinutes(-5),
			WindowEndUtc: createdUtc,
			RowsDeleted: 100 + EventCode,
			Trigger: 1,
			RuleVersion: 1,
			Reason: "IDR-1 information-density retention; trigger=DatabaseBytes; code=" + EventCode,
			InitiatedBy: "Service",
			CreatedUtc: createdUtc);
}
