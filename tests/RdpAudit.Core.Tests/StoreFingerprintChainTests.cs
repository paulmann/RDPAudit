/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StoreFingerprintChainTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: B19 regression for the pure fingerprint-chain rules. The four states an operator acts on
//          (Ok / Missing / Unreadable / ChainBroken) are decided here, from two immutable inputs and a list of
//          findings, so every case is driven without a file system: an edited payload, a re-ordered chain, a
//          removed middle entry, a deleted TAIL (which only the sealed tip can reveal), a rolled-back chain,
//          an unreadable file and a pristine first run.
//          The point of the test set is the DIFFERENCE between the states: "we have nothing" and "something
//          that was recorded is gone" must never produce the same verdict, because that difference is exactly
//          what B19 says was missing.
//          The findings themselves are pinned here as well, because a verdict is only as good as the sentence
//          it arrives in: a finding that asserts two digests differ must never print two values that read as
//          identical, and an alarm that accuses a chain of being replaced while showing equal values is an
//          alarm the operator learns to skip.
// Depends: StoreFingerprintChain, StoreFingerprint, xUnit
// Extends: Add a case here for every new rule in StoreFingerprintChain.Verify.

using RdpAudit.Core.Integrity;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class StoreFingerprintChainTests
{
	private static readonly DateTime T0 = new(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc);

	// ── Digest ───────────────────────────────────────────────────────────────────

	[Fact]
	public void ComputeDigest_IsStable_AndCoversEveryHashedField()
	{
		StoreFingerprintChainEntry entry = Entry(1, StoreFingerprintChain.GenesisDigest, T0, clean: true, rows: 10);
		string digest = StoreFingerprintChain.ComputeDigest(entry);

		Assert.Equal(digest, StoreFingerprintChain.ComputeDigest(entry));
		Assert.True(StoreFingerprintChain.IsDigestShaped(digest));

		// Every field that decides whether an entry is trustworthy must move the digest, or editing it would
		// be invisible - which is precisely the property the pre-B19 document lacked.
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(entry with { Sequence = 2 }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(entry with { CapturedUtc = T0.AddMinutes(1) }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(entry with { CleanShutdown = false }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(entry with { CapturedBy = "Schedule" }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(entry with { PreviousDigest = new string('a', 64) }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(
			entry with { Fingerprint = entry.Fingerprint with { DatabaseBytes = 999 } }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(
			entry with { Fingerprint = entry.Fingerprint with { LastIngestionSequence = 99 } }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(
			entry with { Fingerprint = entry.Fingerprint with { LedgerChainedRows = 7 } }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(
			entry with { Fingerprint = entry.Fingerprint with { LedgerChainIntact = false } }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(
			entry with { Fingerprint = entry.Fingerprint with { AppliedMigrations = ["M1", "M2"] } }));
		Assert.NotEqual(digest, StoreFingerprintChain.ComputeDigest(
			entry with { Fingerprint = entry.Fingerprint with { DatabaseLastWriteUtc = T0 } }));
	}

	/// <summary>A dictionary's enumeration order is not part of the fingerprint's meaning. A digest that
	/// depended on it would report tampering after a harmless refactor - the false alarm that makes an alarm
	/// stop being read.</summary>
	[Fact]
	public void ComputeDigest_IsIndependentOfTableCountEnumerationOrder()
	{
		StoreFingerprint first = new()
		{
			CapturedUtc = T0,
			TableRowCounts = new Dictionary<string, long>(StringComparer.Ordinal) { ["RawEvents"] = 1, ["Alerts"] = 2, ["Sessions"] = 3 },
		};
		StoreFingerprint second = new()
		{
			CapturedUtc = T0,
			TableRowCounts = new Dictionary<string, long>(StringComparer.Ordinal) { ["Sessions"] = 3, ["Alerts"] = 2, ["RawEvents"] = 1 },
		};

		StoreFingerprintChainEntry left = Entry(1, StoreFingerprintChain.GenesisDigest, T0, clean: true, rows: 1) with { Fingerprint = first };
		StoreFingerprintChainEntry right = Entry(1, StoreFingerprintChain.GenesisDigest, T0, clean: true, rows: 1) with { Fingerprint = second };

		Assert.Equal(StoreFingerprintChain.ComputeDigest(left), StoreFingerprintChain.ComputeDigest(right));
	}

	/// <summary>Digesting a null fingerprint must not throw: an entry read from a truncated file is verified
	/// (and rejected) rather than crashing the start-up path.</summary>
	[Fact]
	public void ComputeDigest_WithNoFingerprintPayload_DoesNotThrow()
	{
		StoreFingerprintChainEntry entry = new() { Sequence = 1, CapturedUtc = T0, Fingerprint = null! };
		Assert.True(StoreFingerprintChain.IsDigestShaped(StoreFingerprintChain.ComputeDigest(entry)));
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("abc")]
	[InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
	public void IsDigestShaped_RejectsAnythingButHexOfTheRightLength(string? value)
		=> Assert.False(StoreFingerprintChain.IsDigestShaped(value));

	[Fact]
	public void GenesisDigest_IsDistinguishableFromAnUnfilledField()
	{
		Assert.Equal(StoreFingerprintChain.DigestHexLength, StoreFingerprintChain.GenesisDigest.Length);
		Assert.True(StoreFingerprintChain.IsDigestShaped(StoreFingerprintChain.GenesisDigest));
		Assert.NotEqual(string.Empty, StoreFingerprintChain.GenesisDigest);
	}

	// ── Verify: the four states ──────────────────────────────────────────────────

	/// <summary>PRistine: no chain, no tip. This is Ok with zero entries and says so - it must not be reported
	/// as Missing, because nothing that was recorded is absent.</summary>
	[Fact]
	public void Verify_WithNoChainAndNoTip_IsOkAndSaysThereIsNothingYet()
	{
		StoreFingerprintChainVerification verification = VerifyChain([], tip: null);

		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.False(verification.IsAlarming);
		Assert.Equal(0, verification.EntryCount);
		Assert.Null(verification.Baseline);
		Assert.Contains("no chain to verify", verification.Message, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Verify_WithAValidChainAndMatchingTip_IsOk()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(3);
		StoreFingerprintChainVerification verification = VerifyChain(chain, StoreFingerprintChain.Seal(chain));

		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.False(verification.IsAlarming);
		Assert.Equal(3, verification.EntryCount);
		Assert.Equal(chain[^1].Digest, verification.Tip!.Digest);
		Assert.Contains("verifies", verification.Message, StringComparison.OrdinalIgnoreCase);

		// A tip whose length AND head both match the chain has nothing to report. Returning findings here - even
		// "informational" ones - is what makes an operator stop reading the message that does matter.
		Assert.Empty(verification.Findings);
	}

	/// <summary>An edited payload is the case the pre-B19 document could not see at all.</summary>
	[Fact]
	public void Verify_WhenAnEntryWasEdited_IsChainBroken()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(3);
		chain[1] = chain[1] with { Fingerprint = chain[1].Fingerprint with { DatabaseBytes = 1 } };

		StoreFingerprintChainVerification verification = VerifyChain(chain, StoreFingerprintChain.Seal(chain));

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		Assert.True(verification.IsAlarming);
		Assert.Contains(verification.Findings, finding => finding.Contains("does not match its own digest", StringComparison.Ordinal));
	}

	/// <summary>Removing a middle entry leaves a self-consistent-looking sequence of files; only the linkage
	/// reveals it.</summary>
	[Fact]
	public void Verify_WhenAMiddleEntryWasRemoved_IsChainBroken()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(4);
		List<StoreFingerprintChainEntry> withHole = [chain[0], chain[1], chain[3]];
		StoreFingerprintChainVerification verification = VerifyChain(withHole, StoreFingerprintChain.Seal(chain));

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		Assert.Contains(verification.Findings, finding => finding.Contains("does not link to its predecessor", StringComparison.Ordinal));
	}

	/// <summary>A removed TAIL is a prefix of a valid chain and verifies as a chain. Only the sealed tip knows
	/// how long it should be - this is the entire reason the tip exists.</summary>
	[Fact]
	public void Verify_WhenTheTailWasDeleted_IsMissing_NotOk()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(4);
		StoreFingerprintChainVerification verification = VerifyChain(chain[..2], StoreFingerprintChain.Seal(chain));

		Assert.True(verification.State == StoreFingerprintChainState.Missing, verification.Message);
		Assert.True(verification.IsAlarming);
		Assert.Contains("DELETED", verification.Message, StringComparison.Ordinal);
		Assert.NotEqual(StoreFingerprintChainState.Ok, verification.State);
	}

	/// <summary>The opposite direction - more entries than the tip, or a different head - is a rollback to an
	/// older consistent copy or a substituted chain, which is ChainBroken rather than Missing. The two facts are
	/// reported as two findings, so neither sentence has to carry a value it cannot show.</summary>
	[Fact]
	public void Verify_WhenTheChainWasRolledBack_IsChainBroken()
	{
		List<StoreFingerprintChainEntry> older = BuildChain(2);
		List<StoreFingerprintChainEntry> newer = BuildChain(4);

		StoreFingerprintChainVerification verification = VerifyChain(newer, StoreFingerprintChain.Seal(older));

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		Assert.Contains("rolled back", verification.Message, StringComparison.OrdinalIgnoreCase);

		// The length finding names the two lengths and nothing else, so it cannot print values that look equal.
		string lengthFinding = Assert.Single(
			verification.Findings,
			finding => finding.Contains("accounts for", StringComparison.Ordinal));
		Assert.Contains("2 chain entr(ies)", lengthFinding, StringComparison.Ordinal);
		Assert.Contains("4 are on disk", lengthFinding, StringComparison.Ordinal);

		// The head finding prints both digests whole, so the difference it asserts is visible in the text.
		string headFinding = Assert.Single(
			verification.Findings,
			finding => finding.Contains("head digest", StringComparison.Ordinal));
		Assert.Contains(older[^1].Digest, headFinding, StringComparison.Ordinal);
		Assert.Contains(newer[^1].Digest, headFinding, StringComparison.Ordinal);
	}

	[Fact]
	public void Verify_WhenTheHeadDigestWasSubstituted_IsChainBroken()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(3);
		StoreFingerprintSealedTip tip = StoreFingerprintChain.Seal(chain) with { HeadDigest = new string('b', 64) };

		StoreFingerprintChainVerification verification = VerifyChain(chain, tip);

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
	}

	/// <summary>The invariant every tip comparison rests on: a finding that asserts two digests DIFFER must never
	/// print two values that read as identical. Twelve hex characters of two different digests can coincide, and
	/// that is exactly how a substituted head was reported as "the sealed tip records 1 entr(ies) with head
	/// 668954af9f4e while the chain on disk holds 1 entr(ies) with head 668954af9f4e: the chain was rolled back to
	/// an older copy or replaced with a different one" - a finding that contradicts itself, accuses a chain that
	/// did not move of being replaced, and cannot be acted on. The digests are printed whole instead, and a value
	/// that is not a digest at all is named as such rather than shortened into something that looks like one.</summary>
	[Fact]
	public void Verify_APrintedDigestPairNeverReadsAsIdentical()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(2);
		string head = chain[^1].Digest;
		string substituted = string.Concat(head.AsSpan(0, head.Length - 1), head[^1] == 'a' ? "b" : "a");
		Assert.Equal(head[..12], substituted[..12]);

		StoreFingerprintChainVerification verification = VerifyChain(
			chain,
			StoreFingerprintChain.Seal(chain) with { HeadDigest = substituted });

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		string finding = Assert.Single(
			verification.Findings,
			candidate => candidate.Contains("head digest", StringComparison.Ordinal));
		Assert.Contains(head, finding, StringComparison.Ordinal);
		Assert.Contains(substituted, finding, StringComparison.Ordinal);

		// The tip accounts for exactly the entries that are on disk, so nothing was rolled back and nothing may
		// say it was: only the head differs, and the finding says only that.
		Assert.DoesNotContain("rolled back", verification.Message, StringComparison.OrdinalIgnoreCase);
		Assert.Single(verification.Findings);

		// A chain whose head digest is not a digest at all (a truncated or replaced field) is still named
		// apart from the digest it is compared against, instead of being cut to twelve characters.
		StoreFingerprintChainEntry replaced = chain[^1] with { Digest = "not a digest" };
		List<StoreFingerprintChainEntry> garbage = [chain[0], replaced];
		StoreFingerprintChainVerification unreadable = VerifyChain(garbage, StoreFingerprintChain.Seal(chain));

		Assert.Equal(StoreFingerprintChainState.ChainBroken, unreadable.State);
		string ownDigest = Assert.Single(
			unreadable.Findings,
			candidate => candidate.Contains("does not match its own digest", StringComparison.Ordinal));
		Assert.Contains("not a 64-character hex digest", ownDigest, StringComparison.Ordinal);
		Assert.Contains(StoreFingerprintChain.ComputeDigest(replaced), ownDigest, StringComparison.Ordinal);
	}

	/// <summary>"We could not look" must never render as "we looked and it was fine".</summary>
	[Fact]
	public void Verify_WhenPartOfTheChainCouldNotBeRead_IsUnreadable()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(2);
		StoreFingerprintChainVerification verification = StoreFingerprintChain.Verify(
			chain,
			StoreFingerprintChain.Seal(chain),
			tipReadable: true,
			unreadableFindings: ["fingerprint-0000000003.json could not be read: JsonException - truncated."]);

		Assert.Equal(StoreFingerprintChainState.Unreadable, verification.State);
		Assert.True(verification.IsAlarming);
		Assert.Contains("UNVERIFIED", verification.Message, StringComparison.Ordinal);
	}

	/// <summary>An unreadable tip means the chain's length is unknown, so a deleted tail can no longer be
	/// ruled out. Reporting "Ok" here would be the quiet failure this whole mechanism exists to prevent.</summary>
	[Fact]
	public void Verify_WhenTheTipCouldNotBeRead_IsUnreadable()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(2);
		StoreFingerprintChainVerification verification = StoreFingerprintChain.Verify(
			chain,
			sealedTip: null,
			tipReadable: false,
			unreadableFindings: ["The sealed fingerprint tip exists but is NOT a protected envelope."]);

		Assert.Equal(StoreFingerprintChainState.Unreadable, verification.State);
	}

	[Fact]
	public void Verify_WithNoTipAndAnEmptyChain_IsOk()
	{
		StoreFingerprintChainVerification verification = VerifyChain([], tip: null, tipReadable: true);

		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.Null(verification.Tip);
	}

	/// <summary>The states must be different answers, not different names for the same thing. B24 added the
	/// fifth one, and this guard makes adding a sixth a deliberate act rather than something a writer can do by
	/// inventing an enum member nobody told the verifier about.</summary>
	[Fact]
	public void TheFiveStatesAreDistinct()
	{
		HashSet<StoreFingerprintChainState> states = Enum.GetValues<StoreFingerprintChainState>().ToHashSet();
		Assert.Equal(5, states.Count);
		Assert.Contains(StoreFingerprintChainState.Ok, states);
		Assert.Contains(StoreFingerprintChainState.Missing, states);
		Assert.Contains(StoreFingerprintChainState.Unreadable, states);
		Assert.Contains(StoreFingerprintChainState.ChainBroken, states);
		Assert.Contains(StoreFingerprintChainState.Interrupted, states);
	}

	// ── The interrupted write (B24) ──────────────────────────────────────────────

	/// <summary>A tip that stops exactly one entry short of the chain is what a capture cut short between
	/// appending an entry and re-sealing the tip leaves behind. When the durable write intent names that same
	/// entry - same count, same sequence, same digest - the verdict is <c>Interrupted</c>: the store was
	/// interrupted, and saying "rolled back or replaced" about it is the false tamper alarm B24 removes.</summary>
	[Fact]
	public void Verify_WhenTheTipStopsOneEntryShortAndTheIntentCorroboratesIt_IsInterrupted()
	{
		(List<StoreFingerprintChainEntry> chain, StoreFingerprintSealedTip tip, StoreFingerprintWriteIntent intent) =
			BuildInterruptedState(sealedEntries: 3);

		StoreFingerprintChainVerification verification = VerifyChain(chain, tip, intent);

		Assert.Equal(StoreFingerprintChainState.Interrupted, verification.State);
		Assert.True(verification.IsAlarming);

		// A recoverable state is still a state: it reaches the operator through the same record, with the same
		// kind of finding, as every other non-Ok verdict - it is not a silence and not an Ok with a footnote.
		string finding = Assert.Single(verification.Findings);
		Assert.Contains("durable write intent", finding, StringComparison.Ordinal);
		Assert.Contains(chain[^1].Digest, finding, StringComparison.Ordinal);
		Assert.Contains("interrupted", verification.Message, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("rolled back", verification.Message, StringComparison.OrdinalIgnoreCase);

		// Nothing that was already recorded is missing, and the message says how it ends.
		Assert.Equal(chain.Count, verification.EntryCount);
		Assert.Equal(chain[^1].Digest, verification.Tip!.Digest);

		// The state is not an accusation of editing: every entry still verifies against its own digest, which is
		// what the empty "broken" path above proves from the other side.
		Assert.DoesNotContain(verification.Findings, item => item.Contains("does not match its own digest", StringComparison.Ordinal));
	}

	/// <summary>The property that keeps the recoverable state from being an escape hatch: the SAME on-disk shape
	/// without the intent is the strict verdict, unchanged. Deleting the intent therefore removes the soft
	/// reading instead of earning it.</summary>
	[Fact]
	public void Verify_TheSameShortTipWithoutTheIntent_IsChainBroken()
	{
		(List<StoreFingerprintChainEntry> chain, StoreFingerprintSealedTip tip, _) = BuildInterruptedState(sealedEntries: 3);

		StoreFingerprintChainVerification verification = VerifyChain(chain, tip, intent: null);

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		Assert.Contains("OLDER chain", verification.Message, StringComparison.Ordinal);
	}

	/// <summary>An intent that does not match the entry it claims to describe explains nothing: it is not
	/// evidence about THIS append, and the strict verdict stands. The three ways it can fail are checked
	/// separately because each is a different claim - how many entries, which sequence, which digest.</summary>
	[Theory]
	[InlineData("count")]
	[InlineData("sequence")]
	[InlineData("digest")]
	public void Verify_WhenTheIntentDoesNotMatchTheAppendedEntry_IsChainBroken(string mismatch)
	{
		(List<StoreFingerprintChainEntry> chain, StoreFingerprintSealedTip tip, StoreFingerprintWriteIntent intent) =
			BuildInterruptedState(sealedEntries: 3);

		StoreFingerprintWriteIntent wrong = mismatch switch
		{
			"count" => intent with { ExpectedEntryCount = intent.ExpectedEntryCount + 1 },
			"sequence" => intent with { ExpectedHeadSequence = intent.ExpectedHeadSequence + 1 },
			_ => intent with { ExpectedHeadDigest = new string('e', 64) },
		};

		StoreFingerprintChainVerification verification = VerifyChain(chain, tip, wrong);

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
	}

	/// <summary>An intent from a layout this build does not read is an intent it cannot check, and an unchecked
	/// claim is not a claim: the strict verdict stands rather than the version being ignored.</summary>
	[Fact]
	public void Verify_WhenTheIntentIsAnotherFormatVersion_IsChainBroken()
	{
		(List<StoreFingerprintChainEntry> chain, StoreFingerprintSealedTip tip, StoreFingerprintWriteIntent intent) =
			BuildInterruptedState(sealedEntries: 3);

		StoreFingerprintChainVerification verification =
			VerifyChain(chain, tip, intent with { FormatVersion = StoreFingerprintWriteIntent.CurrentFormatVersion + 1 });

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
	}

	/// <summary>The strongest form of "this does not weaken detection": a PERFECT intent - one that matches the
	/// appended entry exactly - cannot explain away an edit to an entry that was already sealed. The tamper is
	/// reported, and the interrupted reading is not even considered, because the chain contradicts itself.</summary>
	[Fact]
	public void Verify_WithAPerfectIntentAnEditedEntryIsStillChainBroken()
	{
		(List<StoreFingerprintChainEntry> chain, StoreFingerprintSealedTip tip, StoreFingerprintWriteIntent intent) =
			BuildInterruptedState(sealedEntries: 3);

		chain[1] = chain[1] with { Fingerprint = chain[1].Fingerprint with { DatabaseBytes = 1 } };

		StoreFingerprintChainVerification verification = VerifyChain(chain, tip, intent);

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		Assert.Contains(verification.Findings, item => item.Contains("does not match its own digest", StringComparison.Ordinal));
	}

	/// <summary>An intent left over from a write that DID complete explains nothing, and is not reported: the tip
	/// and the chain agree, so there is no discrepancy for it to explain, and inventing a finding for it would
	/// make every completed capture noisy after a crash that did no damage.</summary>
	[Fact]
	public void Verify_WithAStaleIntentAndAnAgreeingTip_IsOk()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(3);
		StoreFingerprintSealedTip tip = StoreFingerprintChain.Seal(chain);

		StoreFingerprintChainVerification verification = VerifyChain(
			chain,
			tip,
			new StoreFingerprintWriteIntent
			{
				ExpectedEntryCount = 4,
				ExpectedHeadSequence = 4,
				ExpectedHeadDigest = new string('f', 64),
				StartedUtc = T0,
			});

		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.Empty(verification.Findings);
	}

	/// <summary>A tip that stops one entry short and does NOT seal the chain without that entry is not the
	/// interrupted shape at all: the intent cannot vouch for a tip that describes some other chain.</summary>
	[Fact]
	public void Verify_WhenTheShortTipDoesNotSealTheRemainderOfTheChain_IsChainBroken()
	{
		(List<StoreFingerprintChainEntry> chain, StoreFingerprintSealedTip tip, StoreFingerprintWriteIntent intent) =
			BuildInterruptedState(sealedEntries: 3);

		StoreFingerprintChainVerification verification =
			VerifyChain(chain, tip with { HeadDigest = new string('a', 64) }, intent);

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
	}

	/// <summary>A tail that is genuinely missing stays Missing no matter what intent is on disk: the intent
	/// describes an append, and an append cannot delete anything.</summary>
	[Fact]
	public void Verify_WhenTheTailWasDeleted_AnIntentDoesNotTurnItIntoInterrupted()
	{
		List<StoreFingerprintChainEntry> full = BuildChain(4);
		StoreFingerprintChainEntry appended = full[^1];

		StoreFingerprintChainVerification verification = VerifyChain(
			full[..3],
			StoreFingerprintChain.Seal(full),
			new StoreFingerprintWriteIntent
			{
				ExpectedEntryCount = appended.Sequence,
				ExpectedHeadSequence = appended.Sequence,
				ExpectedHeadDigest = appended.Digest,
				StartedUtc = T0,
			});

		Assert.Equal(StoreFingerprintChainState.Missing, verification.State);
	}

	/// <summary>An unreadable file means the chain's true length is unknown, so the "tip is exactly one append
	/// behind" claim cannot be made about a folder that could not be read in full: the intent is not allowed to
	/// fill that gap, and the verdict stays the strict one it already was.</summary>
	[Fact]
	public void Verify_WhenAFileCouldNotBeRead_AnIntentDoesNotTurnItIntoInterrupted()
	{
		(List<StoreFingerprintChainEntry> chain, StoreFingerprintSealedTip tip, StoreFingerprintWriteIntent intent) =
			BuildInterruptedState(sealedEntries: 3);

		StoreFingerprintChainVerification verification = StoreFingerprintChain.Verify(
			chain,
			tip,
			tipReadable: true,
			unreadableFindings: ["fingerprint-0000000005.json could not be read: JsonException - truncated."],
			writeIntent: intent);

		Assert.NotEqual(StoreFingerprintChainState.Interrupted, verification.State);
		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		Assert.Contains(
			verification.Findings,
			item => item.Contains("could not be read", StringComparison.Ordinal));
	}

	// ── The sealed tip's fields (B23) ────────────────────────────────────────────

	/// <summary>HeadSequence is cross-checked, not read and forgotten: the tip names the entry at position
	/// EntryCount, so that entry must carry exactly the sequence the tip records. A tip whose own two fields
	/// disagree with the chain was not written for this chain, and the finding prints both numbers.</summary>
	[Fact]
	public void Verify_WhenTheTipHeadSequenceWasReplaced_IsChainBroken()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(3);
		StoreFingerprintSealedTip tip = StoreFingerprintChain.Seal(chain) with { HeadSequence = 99 };

		StoreFingerprintChainVerification verification = VerifyChain(chain, tip);

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		string finding = Assert.Single(
			verification.Findings,
			item => item.Contains("sequence", StringComparison.Ordinal));
		Assert.Contains("99", finding, StringComparison.Ordinal);
		Assert.Contains("3", finding, StringComparison.Ordinal);
	}

	/// <summary>The advisory field, pinned so the decision is a decision: SealedUtc is reported, never compared.
	/// A tip whose sealing time was rewritten still describes the same chain, and a verdict that moved here
	/// would be an alarm about a clock.</summary>
	[Fact]
	public void Verify_WhenTheTipSealingTimeWasReplaced_LeavesTheVerdictUnchanged()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(3);
		StoreFingerprintSealedTip tip = StoreFingerprintChain.Seal(chain);

		StoreFingerprintChainVerification original = VerifyChain(chain, tip);
		StoreFingerprintChainVerification edited = VerifyChain(chain, tip with { SealedUtc = tip.SealedUtc.AddYears(5) });

		Assert.Equal(StoreFingerprintChainState.Ok, edited.State);
		Assert.Equal(original.State, edited.State);
		Assert.Equal(original.EntryCount, edited.EntryCount);
		Assert.Equal(original.Findings.Count, edited.Findings.Count);
		Assert.Equal(original.Message, edited.Message);
		Assert.NotEqual(original.SealedTip!.SealedUtc, edited.SealedTip!.SealedUtc);
	}

	// ── B22: no dereference, whatever the file says ──────────────────────────────

	/// <summary>A null in any field this layout always writes is named, so the reader can report "we could not
	/// read this entry" instead of crashing on a dereference or hashing an invented empty value.</summary>
	[Fact]
	public void DescribeNullField_NamesAFieldThatCarriesNothing()
	{
		StoreFingerprintChainEntry entry = Entry(1, StoreFingerprintChain.GenesisDigest, T0, clean: true, rows: 1);
		Assert.Null(StoreFingerprintChain.DescribeNullField(entry));

		Assert.Equal("CapturedBy", StoreFingerprintChain.DescribeNullField(entry with { CapturedBy = null! }));
		Assert.Equal("PreviousDigest", StoreFingerprintChain.DescribeNullField(entry with { PreviousDigest = null! }));
		Assert.Equal("Digest", StoreFingerprintChain.DescribeNullField(entry with { Digest = null! }));
		Assert.Equal("Fingerprint", StoreFingerprintChain.DescribeNullField(entry with { Fingerprint = null! }));
		Assert.Equal(
			"Fingerprint.CapturedBy",
			StoreFingerprintChain.DescribeNullField(entry with { Fingerprint = entry.Fingerprint with { CapturedBy = null! } }));
		Assert.Equal(
			"Fingerprint.LedgerChainHead",
			StoreFingerprintChain.DescribeNullField(entry with { Fingerprint = entry.Fingerprint with { LedgerChainHead = null! } }));
		Assert.Equal(
			"Fingerprint.TableRowCounts",
			StoreFingerprintChain.DescribeNullField(entry with { Fingerprint = entry.Fingerprint with { TableRowCounts = null! } }));
		Assert.Equal(
			"Fingerprint.AppliedMigrations",
			StoreFingerprintChain.DescribeNullField(entry with { Fingerprint = entry.Fingerprint with { AppliedMigrations = null! } }));

		// The payload itself is asked the same question by the pre-B19 migration, which reads bare
		// StoreFingerprint slots and must not turn one it cannot read into a chain entry that can never be
		// verified. The answer is named without the "Fingerprint." prefix it carries inside an entry.
		StoreFingerprint payload = entry.Fingerprint;
		Assert.Null(StoreFingerprintChain.DescribeNullField(payload));
		Assert.Equal("TableRowCounts", StoreFingerprintChain.DescribeNullField(payload with { TableRowCounts = null! }));
		Assert.Equal("AppliedMigrations", StoreFingerprintChain.DescribeNullField(payload with { AppliedMigrations = null! }));
		Assert.Equal("LedgerChainHead", StoreFingerprintChain.DescribeNullField(payload with { LedgerChainHead = null! }));
		Assert.Equal("CapturedBy", StoreFingerprintChain.DescribeNullField(payload with { CapturedBy = null! }));
	}

	/// <summary>B22, the canonicalization half: every reference-valued field is read through a null-tolerant
	/// form, so no input reaches a dereference. The digest stays deterministic, which is what lets a null-bearing
	/// record be REJECTED by the reader rather than crashing the digest that would have decided it.</summary>
	[Fact]
	public void Canonicalize_WithNullsInEveryReferenceField_DoesNotThrowAndIsDeterministic()
	{
		StoreFingerprintChainEntry entry = new()
		{
			Sequence = 1,
			CapturedUtc = T0,
			CapturedBy = null!,
			PreviousDigest = null!,
			Digest = null!,
			Fingerprint = new StoreFingerprint
			{
				CapturedBy = null!,
				TableRowCounts = null!,
				AppliedMigrations = null!,
				LedgerChainHead = null!,
			},
		};

		string canonical = StoreFingerprintChain.Canonicalize(entry);
		Assert.Equal(canonical, StoreFingerprintChain.Canonicalize(entry));
		Assert.True(StoreFingerprintChain.IsDigestShaped(StoreFingerprintChain.ComputeDigest(entry)));

		// A null list and an empty list are the same statement - "no entries recorded" - so they canonicalize
		// alike. A null ELEMENT is a different statement ("a list with one entry, and that entry is nothing"),
		// and it is described by DescribeNullField instead of being silently folded into the empty case.
		Assert.Equal(
			StoreFingerprintChain.Canonicalize(entry with
			{
				Fingerprint = entry.Fingerprint with { AppliedMigrations = [], TableRowCounts = [] },
			}),
			StoreFingerprintChain.Canonicalize(entry with
			{
				Fingerprint = entry.Fingerprint with { AppliedMigrations = null! },
			}));
		Assert.Equal("Fingerprint.AppliedMigrations[]", StoreFingerprintChain.DescribeNullField(
			Entry(1, StoreFingerprintChain.GenesisDigest, T0, clean: true, rows: 1) with
			{
				Fingerprint = Entry(1, StoreFingerprintChain.GenesisDigest, T0, clean: true, rows: 1).Fingerprint with
				{
					AppliedMigrations = [null!],
				},
			}));
	}

	/// <summary>B22 - the contract the whole read path rests on, for hand-built inputs as well as files: whatever
	/// a caller assembles, Verify answers with a state instead of an exception.</summary>
	[Fact]
	public void Verify_WithNullBearingEntries_NeverThrows()
	{
		StoreFingerprintChainEntry empty = new() { Sequence = 1, CapturedUtc = T0, CapturedBy = null!, Fingerprint = null! };
		StoreFingerprintChainEntry nullPayload = new()
		{
			Sequence = 1,
			CapturedUtc = T0,
			Fingerprint = new StoreFingerprint { TableRowCounts = null!, AppliedMigrations = null!, LedgerChainHead = null! },
		};

		foreach (StoreFingerprintChainEntry entry in new[] { empty, nullPayload })
		{
			StoreFingerprintChainEntry linked = entry with { Digest = StoreFingerprintChain.ComputeDigest(entry) };
			StoreFingerprintChainVerification verification =
				StoreFingerprintChain.Verify([linked], StoreFingerprintChain.Seal([linked]), true, []);

			Assert.True(Enum.IsDefined(verification.State));
			Assert.NotNull(verification.Message);
		}
	}

	// ── Baseline selection ───────────────────────────────────────────────────────

	/// <summary>The authoritative baseline is the newest CLEAN-SHUTDOWN entry, not simply the newest one: only
	/// a clean shutdown proves that no writer remained, which is what the comparer's strongest rules rest on.</summary>
	[Fact]
	public void Baseline_PrefersTheNewestCleanShutdownEntry()
	{
		// Entries 1-2 periodic, 3 clean shutdown, 4 periodic again: the baseline must be 3, not 4.
		List<StoreFingerprintChainEntry> chain = BuildChain(4, cleanShutdownAt: 3);

		StoreFingerprintChainVerification verification = VerifyChain(chain, StoreFingerprintChain.Seal(chain));

		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.Equal(3, verification.LastCleanShutdown!.Sequence);
		Assert.Equal(4, verification.LastPeriodic!.Sequence);
		Assert.Same(verification.LastCleanShutdown.Fingerprint, verification.Baseline);
	}

	/// <summary>With no clean-shutdown entry the newest periodic one is used, and the caller can see from
	/// <c>LastCleanShutdown</c> being null that its authority is weaker.</summary>
	[Fact]
	public void Baseline_FallsBackToTheNewestPeriodicEntry()
	{
		List<StoreFingerprintChainEntry> chain = BuildChain(2, cleanShutdownAt: 0);
		StoreFingerprintChainVerification verification = VerifyChain(chain, StoreFingerprintChain.Seal(chain));

		Assert.Null(verification.LastCleanShutdown);
		Assert.NotNull(verification.LastPeriodic);
		Assert.Same(verification.LastPeriodic!.Fingerprint, verification.Baseline);
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static StoreFingerprintChainVerification VerifyChain(
		IReadOnlyList<StoreFingerprintChainEntry> entries,
		StoreFingerprintSealedTip? tip,
		StoreFingerprintWriteIntent? intent = null,
		bool tipReadable = true)
		=> StoreFingerprintChain.Verify(entries, tip, tipReadable, [], intent);

	/// <summary>The on-disk shape of a capture that was cut short between appending its entry and re-sealing the
	/// tip: a chain of <paramref name="sealedEntries"/> + 1 entries, a tip that seals only the first
	/// <paramref name="sealedEntries"/> of them, and the durable write intent that names the appended entry.
	/// Built the way the writer builds it, so a test cannot accidentally describe a shape the writer never
	/// produces.</summary>
	private static (List<StoreFingerprintChainEntry> Chain, StoreFingerprintSealedTip Tip, StoreFingerprintWriteIntent Intent)
		BuildInterruptedState(int sealedEntries)
	{
		List<StoreFingerprintChainEntry> full = BuildChain(sealedEntries + 1);
		StoreFingerprintChainEntry appended = full[^1];
		return (
			full,
			StoreFingerprintChain.Seal(full[..sealedEntries]),
			new StoreFingerprintWriteIntent
			{
				ExpectedEntryCount = appended.Sequence,
				ExpectedHeadSequence = appended.Sequence,
				ExpectedHeadDigest = appended.Digest,
				StartedUtc = appended.CapturedUtc,
			});
	}

	/// <summary>Builds a valid chain of <paramref name="count"/> entries. Entry
	/// <paramref name="cleanShutdownAt"/> is the last one flagged as a clean shutdown (0 disables it).</summary>
	private static List<StoreFingerprintChainEntry> BuildChain(int count, int cleanShutdownAt = -1)
	{
		List<StoreFingerprintChainEntry> chain = [];
		for (int index = 1; index <= count; index++)
		{
			bool clean = index == cleanShutdownAt;
			StoreFingerprintChainEntry entry = Entry(
				index,
				chain.Count > 0 ? chain[^1].Digest : StoreFingerprintChain.GenesisDigest,
				T0.AddHours(index),
				clean,
				rows: index * 10);
			chain.Add(entry);
		}

		return chain;
	}

	private static StoreFingerprintChainEntry Entry(int sequence, string previous, DateTime capturedUtc, bool clean, long rows)
	{
		StoreFingerprintChainEntry entry = new()
		{
			Sequence = sequence,
			CapturedUtc = capturedUtc,
			CleanShutdown = clean,
			CapturedBy = clean ? "Shutdown" : "Schedule",
			PreviousDigest = previous,
			Fingerprint = new StoreFingerprint
			{
				CapturedUtc = capturedUtc,
				CleanShutdown = clean,
				CapturedBy = clean ? "Shutdown" : "Schedule",
				DatabaseBytes = 4096 + sequence,
				WalBytes = 128,
				DatabaseLastWriteUtc = capturedUtc.AddSeconds(-1),
				LastIngestionSequence = rows,
				TableRowCounts = new Dictionary<string, long>(StringComparer.Ordinal)
				{
					["RawEvents"] = rows,
					["Alerts"] = sequence,
				},
				AppliedMigrations = ["20260504215120_InitialCreate"],
				LedgerChainedRows = sequence,
				LedgerUnchainedRows = 0,
				LedgerChainHead = new string('c', 64),
				LedgerChainIntact = true,
			},
		};
		return entry with { Digest = StoreFingerprintChain.ComputeDigest(entry) };
	}
}
