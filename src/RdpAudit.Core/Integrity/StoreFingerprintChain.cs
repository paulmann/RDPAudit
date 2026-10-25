/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StoreFingerprintChain.cs
// Project: RdpAudit.Core (RdpAudit.Core.Integrity)
// Purpose: The fingerprint CHAIN: an ordered list of fingerprint records in which every record carries the
//          digest of the one before it, plus the rules that decide whether the list on disk is the list that
//          was written (B19).
//          Why a chain rather than one rewritten JSON document (the pre-B19 layout):
//            - Deleting the LAST record was invisible. With one document per slot, removing the file left
//              "no fingerprint yet", which the comparer reports as "nothing to compare against" - a state
//              indistinguishable from a fresh install, i.e. exactly the quiet substitution this must prevent.
//            - Editing a record was invisible too. The document held no self-check, so a forged fingerprint
//              that claimed fewer rows simply replaced the honest one.
//          The chain fixes the second outright and the first as far as it can be fixed from inside the same
//          directory: every record is covered by its own digest, and a record removed from the MIDDLE breaks
//          the linkage, so it is reported as `ChainBroken`. Removing the TAIL cannot be detected by the chain
//          alone - a prefix of a valid chain is a valid chain - which is why the chain is always read
//          together with the SEALED TIP: a separate, protected record of how many entries the chain should
//          hold and what its head digest is. Tip and chain disagreeing in the "fewer entries than the tip
//          declares" direction is reported as `Missing`, not as "no data".
//          The states are deliberately distinguishable, because "we have nothing", "something that used to be
//          here is gone" and "we were cut short while writing" must never render the same way to an operator:
//            Ok          - the chain verifies and matches the sealed tip (or there is no tip and the chain is
//                          empty, which is a first run and nothing is wrong).
//            Missing     - the sealed tip accounts for entries that are not on disk (a deleted tail), or the
//                          chain directory itself is gone while a tip exists.
//            Unreadable  - an entry file, or the sealed tip, exists but cannot be read, parsed or unsealed.
//                          "We could not look" is never reported as "we looked and it was fine".
//            ChainBroken - the records are internally inconsistent (digest mismatch, broken linkage,
//                          sequence gap) or they contradict the tip in the other direction (a rollback to an
//                          older consistent copy, or a substituted head).
//            Interrupted - the chain holds exactly one entry more than the tip accounts for, and a durable
//                          write INTENT that was written before that entry corroborates it: the tip is the seal
//                          of the chain WITHOUT that entry, so a capture was cut short between appending the
//                          entry and re-sealing the tip (B24). Without the intent the identical on-disk shape is
//                          ChainBroken, which is what makes the recoverable reading impossible to obtain by
//                          deleting a file: an attacker who wants it must leave a corroborating intent behind,
//                          and one who can write that could seal the tip itself instead.
//          HONEST LIMIT - no unforgeability is claimed anywhere, here or in the docs. A local administrator
//          can delete the chain, delete the sealed tip, or (for the DPAPI LocalMachine scope) re-seal a
//          forged tip, because every key available to the service is available to that administrator on the
//          same machine. The goal is narrower and achievable: make a QUIET substitution hard and its traces
//          loud. Anyone who removes the chain while leaving the tip gets `Missing`; anyone who rewrites a
//          record gets `ChainBroken`; anyone who breaks DPAPI's integrity check gets `Unreadable`; and the
//          one soft reading - `Interrupted` - is both loud and no easier to reach than the `Ok` an attacker
//          gets by re-sealing the tip that is already the documented weak point.
// Depends: StoreFingerprint
// Extends: Raise StoreFingerprintChainEntry.CurrentFormatVersion when the meaning of a hashed field
//          changes, and keep the old reader working: a chain written by an older build must verify or be
//          reported as a version mismatch, never silently misread.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Integrity;

/// <summary>What the chain on disk looks like, as one of five states an operator can act on.</summary>
public enum StoreFingerprintChainState
{
	/// <summary>The chain verifies and agrees with the sealed tip.</summary>
	Ok = 0,

	/// <summary>Entries the sealed tip accounts for are not on disk (a deleted tail, or a removed file).</summary>
	Missing = 1,

	/// <summary>An entry file or the sealed tip exists but could not be read, parsed or unsealed.</summary>
	Unreadable = 2,

	/// <summary>The records are internally inconsistent, or they contradict the sealed tip in the
	/// "substituted / rolled back" direction.</summary>
	ChainBroken = 3,

	/// <summary>A capture was cut short between appending an entry and re-sealing the tip: the chain holds
	/// exactly one entry more than the tip accounts for, that entry is the one a durable write intent
	/// (<see cref="StoreFingerprintWriteIntent"/>) declared, and the tip is the seal of the chain without it.
	/// Nothing that was already recorded is missing and no digest fails, so this is NOT the "rolled back or
	/// replaced" alarm - it is a crash or a power loss, and the next successful capture re-seals the tip over
	/// the full chain. It is still a non-<see cref="Ok"/> state: it reaches the operator through the same
	/// signals as every other one, because "this host was interrupted mid-write" is a fact worth recording (and
	/// the absence of the matching intent is what turns the same observation into
	/// <see cref="ChainBroken"/>).</summary>
	Interrupted = 4,
}

/// <summary>One link of the fingerprint chain: a fingerprint plus the digest of its predecessor and its
/// own digest. Immutable, and serialized as the file body, so the digest covers exactly what is stored.
/// Every field below is marked <see cref="JsonRequiredAttribute"/>: a reader that silently substituted a
/// default for a missing field would compare against a record nobody wrote - a file with the <c>Sequence</c>
/// property removed would be reported as "an entry was removed or renumbered" when nothing was removed, and a
/// file with a renamed property would be reported as an edited one. A missing field is "we could not read this
/// entry" (Unreadable), which is a loud state and an accurate sentence. This changes no layout: the writer
/// always emits every field, so nothing already on disk stops being readable.</summary>
public sealed record StoreFingerprintChainEntry
{
	/// <summary>Layout version of this entry. Raised when the meaning of a hashed field changes.</summary>
	public const int CurrentFormatVersion = 1;

	/// <summary>Layout version of this record.</summary>
	[JsonRequired]
	public int FormatVersion { get; init; } = CurrentFormatVersion;

	/// <summary>1-based position in the chain. Contiguity is checked: a gap means an entry was removed.</summary>
	[JsonRequired]
	public int Sequence { get; init; }

	/// <summary>When this entry was written (UTC).</summary>
	[JsonRequired]
	public DateTime CapturedUtc { get; init; }

	/// <summary>True when this fingerprint was taken as the service shut down. Carried on the entry as well
	/// as inside the fingerprint because it decides whether the entry can serve as the authoritative
	/// baseline, and a reader of the chain must be able to see it without unpacking the payload.</summary>
	[JsonRequired]
	public bool CleanShutdown { get; init; }

	/// <summary>What took it: <c>Shutdown</c> or <c>Schedule</c>.</summary>
	[JsonRequired]
	public string CapturedBy { get; init; } = string.Empty;

	/// <summary>Digest of the previous entry, or <see cref="StoreFingerprintChain.GenesisDigest"/> for the
	/// first one.</summary>
	[JsonRequired]
	public string PreviousDigest { get; init; } = StoreFingerprintChain.GenesisDigest;

	/// <summary>Digest of this entry, computed over every other field including
	/// <see cref="PreviousDigest"/>. Stored so a reader can verify without recomputing from a second source,
	/// and so an edited payload is detectable by comparing the two.</summary>
	[JsonRequired]
	public string Digest { get; init; } = string.Empty;

	/// <summary>The fingerprint itself.</summary>
	[JsonRequired]
	public StoreFingerprint Fingerprint { get; init; } = new();
}

/// <summary>The sealed tip: the protected record of how long the chain should be and what its head digest
/// is. Written through <c>ISecretProtector</c>, so on Windows it is a DPAPI envelope rather than plain JSON.
/// This is the second, independent store that makes a deleted tail visible. Its fields are required for the
/// same reason the entry's are: <c>EntryCount</c> defaulting to 0 would make the store announce "the sealed
/// tip records 0 entr(ies)" - a rollback that never happened - for a file whose property name was merely
/// altered, and the head digest would then be printed as identical on both sides.
/// <para>
/// B23 - what each field is FOR, decided rather than left implicit. The first three describe ONE entry of the
/// chain, the entry at position <c>EntryCount</c>:
/// </para>
/// <list type="bullet">
/// <item><description><c>EntryCount</c> - VERIFIED. Fewer entries on disk than this is
/// <see cref="StoreFingerprintChainState.Missing"/>, more is a contradiction.</description></item>
/// <item><description><c>HeadSequence</c> - VERIFIED. When the claimed position is on disk it must carry
/// exactly this sequence; a divergence means the tip was not written for this chain, because the writer
/// always seals position <c>EntryCount</c>, whose sequence is <c>EntryCount</c> in a chain with no gap. The
/// verdict is <see cref="StoreFingerprintChainState.ChainBroken"/>, and the finding names the two values. It
/// cannot cross-check anything while the claimed position is off the end of the chain (a deleted tail), and
/// the <see cref="StoreFingerprintChainState.Missing"/> verdict stands on its own there.</description></item>
/// <item><description><c>HeadDigest</c> - VERIFIED, as it always was.</description></item>
/// <item><description><c>FormatVersion</c> - VERIFIED. A tip written in a layout this build does not read is
/// reported as <see cref="StoreFingerprintChainState.Unreadable"/> instead of being interpreted field by
/// field, exactly as a chain entry of an unknown version is. Silently accepting it would let a future layout
/// be read under this one's rules.</description></item>
/// <item><description><c>SealedUtc</c> - ADVISORY. It is written, read and reported, and nothing compares it
/// with the chain: it is a wall-clock observation, and no rule here can turn it into evidence without
/// inventing one (a clock that moved backwards is not tampering, and an entry's <c>CapturedUtc</c> is already
/// covered by that entry's own digest). A divergence in this field alone does NOT change the verdict, and
/// <see cref="StoreFingerprintChain.Verify"/> is pinned by a test that says so.</description></item>
/// </list>
/// </summary>
public sealed record StoreFingerprintSealedTip
{
	/// <summary>Layout version of the sealed tip.</summary>
	public const int CurrentFormatVersion = 1;

	/// <summary>Layout version of this record. <b>Verified</b>: a tip whose version this build does not read is
	/// reported as unreadable rather than interpreted.</summary>
	[JsonRequired]
	public int FormatVersion { get; init; } = CurrentFormatVersion;

	/// <summary>Number of entries the chain held when this tip was written. <b>Verified</b> against the chain's
	/// length in both directions.</summary>
	[JsonRequired]
	public int EntryCount { get; init; }

	/// <summary>Digest of the newest entry at that moment. <b>Verified</b> against the entry at position
	/// <see cref="EntryCount"/>.</summary>
	[JsonRequired]
	public string HeadDigest { get; init; } = StoreFingerprintChain.GenesisDigest;

	/// <summary>When the tip was written (UTC). <b>Advisory</b>: it is reported but never compared, so a
	/// divergence in it alone does not change the verdict. See the type remarks.</summary>
	[JsonRequired]
	public DateTime SealedUtc { get; init; }

	/// <summary>Sequence number of the newest entry at that moment. <b>Verified</b> against the sequence of the
	/// entry at position <see cref="EntryCount"/> whenever that position is on disk.</summary>
	[JsonRequired]
	public int HeadSequence { get; init; }
}

/// <summary>The durable write INTENT (B24): a small marker written BEFORE a chain entry is appended and removed
/// AFTER the sealed tip has been re-sealed, so a capture that was interrupted between those two steps can be
/// told apart from a rollback or a substitution.
/// <para>
/// Why the recovery needs it. The write is two steps - append the entry, then re-seal the tip - and a crash
/// between them leaves a chain that is one entry longer than the tip. Without independent evidence of the
/// intent, that shape is indistinguishable from a re-sealed tip over a forged entry, which is why it used to be
/// reported as <see cref="StoreFingerprintChainState.ChainBroken"/>: a "rolled back or replaced" alarm for a
/// store that was merely interrupted, i.e. a false tamper alarm on a power loss.
/// </para>
/// <para>
/// Why the recovery is not a hole. The intent is a claim about an ENTRY, and the verifier accepts it only when
/// the claim matches what is on disk exactly: the same entry count, the same sequence and the same digest, the
/// tip sealing precisely the chain without that entry, and no other finding anywhere (an edited entry, a broken
/// linkage or an unreadable file all keep the strict verdict). Deleting the intent file therefore removes the
/// soft reading instead of gaining it - and forging one requires write access to the integrity folder, from
/// which the documented, already-accepted step to a plain `Ok` is to re-seal the tip itself
/// (see <see cref="StoreFingerprintChain"/> remarks). No integrity key is involved: this record is not a
/// signature, it is the missing half of a two-phase write.
/// </para>
/// </summary>
public sealed record StoreFingerprintWriteIntent
{
	/// <summary>Layout version of this record. An intent whose version this build does not read is treated as
	/// absent - the strict verdict then stands - rather than being interpreted.</summary>
	public const int CurrentFormatVersion = 1;

	/// <summary>Layout version of this record.</summary>
	[JsonRequired]
	public int FormatVersion { get; init; } = CurrentFormatVersion;

	/// <summary>How many entries the chain was about to hold once the append completed: the sequence of the
	/// entry being written, because a chain without a gap numbers its entries 1..N.</summary>
	[JsonRequired]
	public int ExpectedEntryCount { get; init; }

	/// <summary>Sequence of the entry being written. Verified against the entry found at
	/// <see cref="ExpectedEntryCount"/>.</summary>
	[JsonRequired]
	public int ExpectedHeadSequence { get; init; }

	/// <summary>Digest of the entry being written. Verified against the entry found at
	/// <see cref="ExpectedEntryCount"/>: an intent that names a different entry explains nothing.</summary>
	[JsonRequired]
	public string ExpectedHeadDigest { get; init; } = string.Empty;

	/// <summary>When the append started (UTC). Advisory, like the tip's sealing time.</summary>
	[JsonRequired]
	public DateTime StartedUtc { get; init; }
}

/// <summary>Everything a reader can learn about the chain: its state, its length, its newest entries and the
/// findings behind a non-Ok state.</summary>
public sealed record StoreFingerprintChainVerification(
	StoreFingerprintChainState State,
	int EntryCount,
	StoreFingerprintChainEntry? Tip,
	StoreFingerprintChainEntry? LastCleanShutdown,
	StoreFingerprintChainEntry? LastPeriodic,
	StoreFingerprintSealedTip? SealedTip,
	bool TipReadable,
	IReadOnlyList<string> Findings,
	string Message)
{
	/// <summary>True when <see cref="State"/> is anything other than <see cref="StoreFingerprintChainState.Ok"/>.
	/// Callers use this to decide whether the state is loud enough to become an anomaly.</summary>
	public bool IsAlarming => State != StoreFingerprintChainState.Ok;

	/// <summary>The fingerprint a start-up comparison should use as its baseline: the newest clean-shutdown
	/// entry when one exists, otherwise the newest entry of any kind. Null when the chain has no entry.</summary>
	public StoreFingerprint? Baseline => LastCleanShutdown?.Fingerprint ?? Tip?.Fingerprint;
}

/// <summary>Computes and verifies the fingerprint chain. Pure: entries in, a verdict out, no file system.</summary>
public static class StoreFingerprintChain
{
	/// <summary>Length of a digest in hex characters (SHA-256).</summary>
	public const int DigestHexLength = 64;

	/// <summary>The <see cref="StoreFingerprintChainEntry.PreviousDigest"/> of the first entry: 64 zeros.
	/// A literal genesis value rather than an empty string keeps "the chain starts here" distinguishable from
	/// "the column was not filled in".</summary>
	public static readonly string GenesisDigest = new('0', DigestHexLength);

	/// <summary>Field separator, for the same reason the ledger chain uses one: a value that contains the
	/// separator cannot be used to shift a field boundary and make two different entries hash alike.</summary>
	private const char FieldSeparator = '\u001f';

	/// <summary>Formats a timestamp for hashing: invariant, fixed width, no time-zone suffix, so a value
	/// round-tripped through JSON always canonicalizes to the same text.</summary>
	public static string FormatTimestamp(DateTime value)
		=> value.ToString("yyyy-MM-ddTHH:mm:ss.FFFFFFF", CultureInfo.InvariantCulture);

	/// <summary>The canonical text an entry hashes over. Exposed so a test can show exactly which bytes a
	/// mismatch covered, and so two readers cannot disagree about what a digest means.
	/// <para>
	/// B22 - TOTAL, deliberately: every reference-valued field is read through a null-tolerant form, so no input
	/// reaches a dereference and the documented "never throws" contract of the read path holds for a record a
	/// file (or a caller) hands over with <c>"TableRowCounts": null</c>, a null predecessor digest or no payload
	/// at all. A null is rendered as the empty value it would have hashed as, which is a deterministic answer and
	/// not an invented one: the reader above rejects an entry that carries a null where this layout always
	/// writes a value (<see cref="DescribeNullField(StoreFingerprintChainEntry)"/>) and reports it as
	/// <see cref="StoreFingerprintChainState.Unreadable"/>, so a null-bearing record is never ACCEPTED here - it
	/// is only never able to crash the digest that decides that.
	/// </para>
	/// </summary>
	public static string Canonicalize(StoreFingerprintChainEntry entry)
	{
		ArgumentNullException.ThrowIfNull(entry);

		StringBuilder builder = new(512);
		Append(builder, "RDPAUDIT-FINGERPRINT-CHAIN-V" + entry.FormatVersion.ToString(CultureInfo.InvariantCulture));
		Append(builder, entry.Sequence.ToString(CultureInfo.InvariantCulture));
		Append(builder, (entry.PreviousDigest ?? string.Empty).ToLowerInvariant());
		Append(builder, FormatTimestamp(entry.CapturedUtc));
		Append(builder, entry.CleanShutdown ? "1" : "0");
		Append(builder, entry.CapturedBy ?? string.Empty);

		StoreFingerprint fingerprint = entry.Fingerprint ?? new StoreFingerprint();
		Append(builder, fingerprint.FormatVersion.ToString(CultureInfo.InvariantCulture));
		Append(builder, FormatTimestamp(fingerprint.CapturedUtc));
		Append(builder, fingerprint.CleanShutdown ? "1" : "0");
		Append(builder, fingerprint.CapturedBy ?? string.Empty);
		Append(builder, fingerprint.DatabaseBytes.ToString(CultureInfo.InvariantCulture));
		Append(builder, fingerprint.WalBytes.ToString(CultureInfo.InvariantCulture));
		Append(builder, fingerprint.DatabaseLastWriteUtc is { } lastWrite ? FormatTimestamp(lastWrite) : "null");
		Append(builder, fingerprint.LastIngestionSequence.ToString(CultureInfo.InvariantCulture));

		// Sorted, because a dictionary's enumeration order is not part of the fingerprint's meaning and a
		// digest that depended on it would report tampering after a harmless refactor. A null dictionary is
		// "no table counts were recorded", which contributes no pairs rather than throwing.
		foreach ((string table, long count) in (fingerprint.TableRowCounts ?? []).OrderBy(
			pair => pair.Key,
			StringComparer.Ordinal))
		{
			Append(builder, table);
			Append(builder, count.ToString(CultureInfo.InvariantCulture));
		}

		// Rendered field by field rather than through string.Join, so a null list and a null element both
		// canonicalize the same way every time instead of depending on an overload's null handling.
		foreach (string? migration in fingerprint.AppliedMigrations ?? [])
		{
			Append(builder, migration ?? string.Empty);
		}

		Append(builder, fingerprint.LedgerChainedRows.ToString(CultureInfo.InvariantCulture));
		Append(builder, fingerprint.LedgerUnchainedRows.ToString(CultureInfo.InvariantCulture));
		Append(builder, (fingerprint.LedgerChainHead ?? string.Empty).ToLowerInvariant());
		Append(builder, fingerprint.LedgerChainIntact ? "1" : "0");
		return builder.ToString();
	}

	/// <summary>Describes the first field that every writer of this layout always emits but that is <c>null</c>
	/// in <paramref name="entry"/> (for example <c>Fingerprint.TableRowCounts</c>), or null when the entry
	/// carries a value in all of them.
	/// <para>
	/// B22 - the reader's half of the decision, and the reason a null does not simply fail a digest. A missing
	/// property is already <see cref="StoreFingerprintChainState.Unreadable"/> (the entry type requires every
	/// field to be PRESENT), and a null is the same situation one step further: the property is there and holds
	/// nothing this layout ever writes. Reporting "the file was edited" (<c>ChainBroken</c>) for it would accuse
	/// a truncated or half-copied file of a substitution; reporting a value we invented for it is what A10
	/// removed. So the entry is treated as one we could not read, and the finding names the field, which turns
	/// a crash into an actionable sentence.
	/// </para>
	/// </summary>
	public static string? DescribeNullField(StoreFingerprintChainEntry entry)
	{
		ArgumentNullException.ThrowIfNull(entry);

		if (entry.CapturedBy is null)
		{
			return "CapturedBy";
		}

		if (entry.PreviousDigest is null)
		{
			return "PreviousDigest";
		}

		if (entry.Digest is null)
		{
			return "Digest";
		}

		if (entry.Fingerprint is null)
		{
			return "Fingerprint";
		}

		string? payloadNullField = DescribeNullField(entry.Fingerprint);
		return payloadNullField is null ? null : "Fingerprint." + payloadNullField;
	}

	/// <summary>The same question for the fingerprint PAYLOAD, named without the "Fingerprint." prefix. It is
	/// separate because the payload is also read outside a chain entry: the pre-B19 document is migrated from a
	/// bare <see cref="StoreFingerprint"/>, and a slot that carries a null in a field this layout always writes
	/// must not be turned into a chain entry that could never be read back (B22).</summary>
	public static string? DescribeNullField(StoreFingerprint fingerprint)
	{
		ArgumentNullException.ThrowIfNull(fingerprint);

		if (fingerprint.CapturedBy is null)
		{
			return "CapturedBy";
		}

		if (fingerprint.LedgerChainHead is null)
		{
			return "LedgerChainHead";
		}

		if (fingerprint.TableRowCounts is null)
		{
			return "TableRowCounts";
		}

		if (fingerprint.AppliedMigrations is null)
		{
			return "AppliedMigrations";
		}

		if (fingerprint.AppliedMigrations.Exists(migration => migration is null))
		{
			return "AppliedMigrations[]";
		}

		return null;
	}

	/// <summary>Lower-case hex SHA-256 of the entry's canonical text.</summary>
	public static string ComputeDigest(StoreFingerprintChainEntry entry)
	{
		byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(Canonicalize(entry)));
		return Convert.ToHexString(digest).ToLowerInvariant();
	}

	/// <summary>True when <paramref name="value"/> looks like a digest this class produces.</summary>
	public static bool IsDigestShaped(string? value)
	{
		if (value is not { Length: DigestHexLength })
		{
			return false;
		}

		foreach (char character in value)
		{
			bool isHex = (character >= '0' && character <= '9')
				|| (character >= 'a' && character <= 'f')
				|| (character >= 'A' && character <= 'F');
			if (!isHex)
			{
				return false;
			}
		}

		return true;
	}

	/// <summary>Verifies an ordered chain against the sealed tip.
	/// <paramref name="entries"/> is the chain as read from disk, ordered by
	/// <see cref="StoreFingerprintChainEntry.Sequence"/>. <paramref name="unreadableFindings"/> carries what
	/// the reader could not read at all: a file that exists but cannot be parsed is evidence for
	/// <see cref="StoreFingerprintChainState.Unreadable"/> and cannot be inferred from the entries that did
	/// parse. <paramref name="writeIntent"/> is the durable marker the writer leaves between appending an entry
	/// and re-sealing the tip; it can turn ONE shape - a tip that stops exactly one entry short of the chain -
	/// from <see cref="StoreFingerprintChainState.ChainBroken"/> into
	/// <see cref="StoreFingerprintChainState.Interrupted"/>, and it can do nothing else.</summary>
	public static StoreFingerprintChainVerification Verify(
		IReadOnlyList<StoreFingerprintChainEntry> entries,
		StoreFingerprintSealedTip? sealedTip,
		bool tipReadable,
		IReadOnlyList<string> unreadableFindings,
		StoreFingerprintWriteIntent? writeIntent = null)
	{
		ArgumentNullException.ThrowIfNull(entries);
		ArgumentNullException.ThrowIfNull(unreadableFindings);

		List<string> findings = [.. unreadableFindings];
		bool broken = false;

		string previousDigest = GenesisDigest;
		int expectedSequence = 1;
		foreach (StoreFingerprintChainEntry entry in entries)
		{
			if (entry.Sequence != expectedSequence)
			{
				findings.Add(string.Format(
					CultureInfo.InvariantCulture,
					"Entry {0} is out of place: the chain reaches it with sequence {1} expected, so an entry was "
						+ "removed or renumbered.",
					entry.Sequence,
					expectedSequence));
				broken = true;
			}

			string recomputed = ComputeDigest(entry);
			if (!string.Equals(recomputed, entry.Digest, StringComparison.OrdinalIgnoreCase))
			{
				findings.Add(string.Format(
					CultureInfo.InvariantCulture,
					"Entry {0} does not match its own digest: it was edited after it was written (stored {1}, "
						+ "recomputed {2}).",
					entry.Sequence,
					RevealDigest(entry.Digest),
					RevealDigest(recomputed)));
				broken = true;
			}

			if (!string.Equals(entry.PreviousDigest, previousDigest, StringComparison.OrdinalIgnoreCase))
			{
				findings.Add(string.Format(
					CultureInfo.InvariantCulture,
					"Entry {0} does not link to its predecessor: it claims previous {1} while the chain reaches "
						+ "it with {2}. An entry was removed from the middle, reordered, or replaced together "
						+ "with everything after it.",
					entry.Sequence,
					RevealDigest(entry.PreviousDigest),
					RevealDigest(previousDigest)));
				broken = true;
			}

			previousDigest = entry.Digest;
			expectedSequence = entry.Sequence + 1;
		}

		StoreFingerprintChainEntry? tip = entries.Count > 0 ? entries[^1] : null;
		StoreFingerprintChainEntry? lastClean = entries.LastOrDefault(entry => entry.CleanShutdown);
		StoreFingerprintChainEntry? lastPeriodic = entries.LastOrDefault(entry => !entry.CleanShutdown);

		// The tip's own claim is checked against the chain in both directions, but they mean different things.
		string? tailFinding = null;
		string? interruptedFinding = null;
		if (sealedTip is not null && tipReadable)
		{
			// EntryCount, HeadSequence and HeadDigest all describe ONE entry: position EntryCount of the chain,
			// whose sequence is EntryCount in a chain with no gap. When that position is on disk the three
			// fields are cross-checked against the entry found there (B23), and the result decides whether the
			// tip is a genuine seal of a prefix of this chain - which is the shape an interrupted re-seal
			// leaves, and also the shape a tip left behind by a rollback leaves.
			StoreFingerprintChainEntry? claimedHead =
				sealedTip.EntryCount >= 1 && sealedTip.EntryCount <= entries.Count
					? entries[sealedTip.EntryCount - 1]
					: null;
			bool tipSealsAPrefixOfTheChain = claimedHead is not null
				&& string.Equals(sealedTip.HeadDigest, claimedHead.Digest, StringComparison.OrdinalIgnoreCase)
				&& sealedTip.HeadSequence == claimedHead.Sequence;

			if (sealedTip.EntryCount > entries.Count)
			{
				tailFinding = string.Format(
					CultureInfo.InvariantCulture,
					"The sealed tip records {0} chain entr(ies) but only {1} are on disk: the newest "
						+ "fingerprint(s) were DELETED after they were written.",
					sealedTip.EntryCount,
					entries.Count);
			}
			else
			{
				// The two remaining ways the tip can contradict the chain are reported as two findings, not as one
				// sentence carrying four values: a sentence that printed both counts and both heads could announce a
				// rollback or a substitution while the values it printed read as identical, and a finding that
				// contradicts itself is worse than no finding - it teaches the operator to skip the alarm. Each
				// finding below therefore states one fact, and every digest it names is printed in full.
				if (sealedTip.EntryCount < entries.Count)
				{
					// B24 - the ONE shape that a durable write intent can explain. The reading is admitted only
					// when nothing else is wrong (no digest mismatch, no broken linkage, no unreadable file, and
					// no sequence or head contradiction), when the tip stops EXACTLY one entry short, when the
					// tip seals precisely the chain without that entry, and when the intent names that same entry
					// by count, sequence and digest. Every one of those is a fact on disk that the intent has to
					// match; an intent that is missing, unreadable, of another version or in any way different
					// leaves the verdict exactly where it was. That is why deleting the intent file cannot earn
					// the softer state - it can only lose it.
					if (!broken
						&& findings.Count == 0
						&& tipSealsAPrefixOfTheChain
						&& sealedTip.EntryCount == entries.Count - 1
						&& IntentExplainsTheAppendedEntry(writeIntent, tip))
					{
						interruptedFinding = string.Format(
							CultureInfo.InvariantCulture,
							"The sealed tip accounts for {0} chain entr(ies) (head {1} at sequence {2}) while {3} are "
								+ "on disk, and the durable write intent declares the entry that is on disk as the one "
								+ "it was about to seal: sequence {4}, digest {5}. The tip is the seal of the chain "
								+ "WITHOUT its newest entry, which is what a capture interrupted between appending an "
								+ "entry and re-sealing the tip leaves behind.",
							sealedTip.EntryCount,
							RevealDigest(sealedTip.HeadDigest),
							sealedTip.HeadSequence,
							entries.Count,
							tip!.Sequence,
							RevealDigest(tip.Digest));
						findings.Add(interruptedFinding);
					}
					else
					{
						broken = true;
						findings.Add(string.Format(
							CultureInfo.InvariantCulture,
							"The sealed tip accounts for {0} chain entr(ies) while {1} are on disk: the tip describes an "
								+ "OLDER chain than the one on disk, so the chain was rolled back to an older copy or the "
								+ "tip was left behind by an interrupted re-seal that left no durable write intent behind "
								+ "to confirm it.",
							sealedTip.EntryCount,
							entries.Count));
					}
				}

				if (interruptedFinding is null
					&& tip is not null
					&& !string.Equals(sealedTip.HeadDigest, tip.Digest, StringComparison.OrdinalIgnoreCase))
				{
					broken = true;
					findings.Add(string.Format(
						CultureInfo.InvariantCulture,
						"The sealed tip's head digest is {0} while the newest entry on disk has digest {1}: the tip "
							+ "and the chain describe different chains, so the newest entry is not the one the tip was "
							+ "written for.",
						RevealDigest(sealedTip.HeadDigest),
						RevealDigest(tip.Digest)));
				}

				// B23 - the tip's remaining field, cross-checked rather than read and ignored. Both values were
				// written by the same writer from the same entry, so a tip whose HeadSequence is not the sequence
				// of the entry it names was not produced by this layout: it is a replaced or hand-edited second
				// store, and it is reported as ChainBroken with the two values in full. It cannot be checked at
				// all when the claimed position is off the end of the chain (the tail was deleted), and the
				// Missing verdict for that case stands on its own.
				if (claimedHead is not null && sealedTip.HeadSequence != claimedHead.Sequence)
				{
					broken = true;
					findings.Add(string.Format(
						CultureInfo.InvariantCulture,
						"The sealed tip records its head at chain sequence {0} while the entry it names (position {1}) "
							+ "carries sequence {2}: the second store was not written for this chain.",
						sealedTip.HeadSequence,
						sealedTip.EntryCount,
						claimedHead.Sequence));
				}
			}
		}

		// Precedence, in order: a chain that contradicts itself is ChainBroken; a chain that a durable write
		// intent shows was left mid-write is Interrupted; a chain shorter than its sealed tip is Missing (the tail
		// is gone); anything else that could not be read is Unreadable. Missing ranks above Unreadable on purpose
		// - an unreadable file can itself be the entry the tip accounts for, and "entries were removed" is the
		// more actionable statement - but the unreadable findings are reported in the message either way, so
		// nothing is dropped. Interrupted ranks below ChainBroken because it is only ever set when no other
		// finding exists, and above Missing because it is the one shape in which the tip is one append behind
		// rather than ahead.
		StoreFingerprintChainState state;
		string message;
		if (broken)
		{
			state = StoreFingerprintChainState.ChainBroken;
			message = string.Format(
				CultureInfo.InvariantCulture,
				"The store-fingerprint chain does not verify ({0} finding(s)). Fingerprints recorded before the "
					+ "break cannot be trusted as evidence of the store's state: {1}",
				findings.Count,
				string.Join(" | ", findings));
		}
		else if (interruptedFinding is not null)
		{
			state = StoreFingerprintChainState.Interrupted;
			message = interruptedFinding
				+ " This is the signature of a capture cut short by a crash or a power loss, not of a rollback or "
				+ "a substitution: nothing that was already recorded is missing, every entry still verifies against "
				+ "its own digest and against the tip's head, and the next capture repairs the store by re-sealing "
				+ "the tip over the full chain, which needs no operator action. The newest entry is not covered by "
				+ "the sealed tip until then. If this host did NOT lose power and the service did NOT crash, treat "
				+ "this as an intrusion attempt instead: the same shape is what a re-sealed tip over an appended "
				+ "forged entry would leave, and it is why the durable write intent is read as evidence rather than "
				+ "as proof.";
		}
		else if (tailFinding is not null)
		{
			state = StoreFingerprintChainState.Missing;
			message = tailFinding
				+ " Any comparison against the remaining chain compares against a baseline that was superseded."
				+ (findings.Count > 0
					? " Additionally, part of the chain could not be read: " + string.Join(" | ", findings)
					: string.Empty);
		}
		else if (findings.Count > 0)
		{
			state = StoreFingerprintChainState.Unreadable;
			message = string.Format(
				CultureInfo.InvariantCulture,
				"Part of the store-fingerprint chain could not be read, so its integrity is UNVERIFIED rather "
					+ "than confirmed: {0}",
				string.Join(" | ", findings));
		}
		else
		{
			state = StoreFingerprintChainState.Ok;
			message = entries.Count == 0
				? "No store fingerprint has been captured yet, so there is no chain to verify."
				: string.Format(
					CultureInfo.InvariantCulture,
					"The store-fingerprint chain verifies: {0} entr(ies), head {1}, last written {2:O} (UTC).",
					entries.Count,
					Short(tip!.Digest),
					entries[^1].CapturedUtc);
		}

		return new StoreFingerprintChainVerification(
			State: state,
			EntryCount: entries.Count,
			Tip: tip,
			LastCleanShutdown: lastClean,
			LastPeriodic: lastPeriodic,
			SealedTip: sealedTip,
			TipReadable: tipReadable,
			Findings: findings,
			Message: message);
	}

	/// <summary>True when <paramref name="intent"/> is a readable intent of this layout whose claim about the
	/// appended entry matches <paramref name="appendedEntry"/> exactly: the same position, the same sequence and
	/// the same digest. Nothing weaker is accepted - an intent for a different entry, a different count or a
	/// different version explains nothing and leaves the strict verdict standing (B24).</summary>
	private static bool IntentExplainsTheAppendedEntry(
		StoreFingerprintWriteIntent? intent,
		StoreFingerprintChainEntry? appendedEntry)
	{
		if (intent is null || appendedEntry is null)
		{
			return false;
		}

		return intent.FormatVersion == StoreFingerprintWriteIntent.CurrentFormatVersion
			&& intent.ExpectedEntryCount == appendedEntry.Sequence
			&& intent.ExpectedHeadSequence == appendedEntry.Sequence
			&& string.Equals(intent.ExpectedHeadDigest, appendedEntry.Digest, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>Builds the sealed tip a chain should be sealed with. Kept here so the writer and any
	/// verifier agree on what the tip of a given chain is.</summary>
	public static StoreFingerprintSealedTip Seal(IReadOnlyList<StoreFingerprintChainEntry> entries)
	{
		ArgumentNullException.ThrowIfNull(entries);
		return new StoreFingerprintSealedTip
		{
			EntryCount = entries.Count,
			HeadDigest = entries.Count > 0 ? entries[^1].Digest : GenesisDigest,
			HeadSequence = entries.Count > 0 ? entries[^1].Sequence : 0,
			SealedUtc = DateTime.UtcNow,
		};
	}

	private static void Append(StringBuilder builder, string value)
	{
		builder.Append(value).Append(FieldSeparator);
	}

	private static string Short(string? digest)
		=> string.IsNullOrEmpty(digest) ? "(none)" : digest[..Math.Min(12, digest.Length)];

	/// <summary>Renders a digest inside a finding that asserts two digests DIFFER. A digest-shaped value is
	/// printed whole (64 hex characters) rather than shortened, because twelve characters of two different
	/// digests can be identical: the earlier "the tip records head 668954af9f4e while the chain holds head
	/// 668954af9f4e - the chain was replaced" is a finding that contradicts what it prints, and an operator
	/// cannot act on it. A value that is not digest-shaped is described by its length and by a digest of its own
	/// text rather than printed, so a hostile file cannot inflate the message and two such values still render
	/// differently instead of looking like the same digest.</summary>
	private static string RevealDigest(string? digest)
	{
		if (IsDigestShaped(digest))
		{
			return digest!;
		}

		if (string.IsNullOrEmpty(digest))
		{
			return "(no digest recorded)";
		}

		// The value itself is NOT printed: it is whatever the file happened to contain, so its length is not
		// bounded. A digest of its text keeps the rendering both short and different from any other value.
		byte[] textDigest = SHA256.HashData(Encoding.UTF8.GetBytes(digest));
		return string.Format(
			CultureInfo.InvariantCulture,
			"(not a {0}-character hex digest: \"{1}\", {2} character(s), text digest {3})",
			DigestHexLength,
			Short(digest),
			digest.Length,
			Convert.ToHexString(textDigest)[..12].ToLowerInvariant());
	}
}
