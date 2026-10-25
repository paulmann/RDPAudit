/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StoreFingerprintChainStoreTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: B19 regression for the on-disk side of the fingerprint chain: the files, the sealed tip and the
//          alarm mirror. Every case here is a REAL file-system mutation an attacker with write access to
//          %ProgramData%\RdpAudit\integrity could perform, and the assertion is that the service reports the
//          matching distinct state afterwards instead of returning "there is no fingerprint yet":
//            - delete the newest entry file          -> Missing
//            - delete an entry from the middle       -> ChainBroken
//            - edit an entry's payload               -> ChainBroken
//            - truncate the sealed tip's payload     -> Unreadable
//            - replace the sealed tip with plaintext -> Unreadable
//          plus the two properties that make the mechanism usable: a pre-B19 document migrates into the chain
//          once, and the key facts reach the mirror sink that sits outside the integrity folder.
//          Every mutation here is defined by the BYTES it changes, never by a position in the file: an edit at
//          "the middle character" lands somewhere different on every run, because the length of the tip's
//          timestamp decides where the middle is. Each case therefore states one outcome it can always observe,
//          including the case where an edit cannot change a single byte the store reads.
//          The test also pins the honest limit: the sealed tip is NOT unforgeable (a process that can run
//          DPAPI LocalMachine can re-seal a forged tip), so no test here claims otherwise - only that a
//          tampered or missing chain stops being silent.
// Depends: StoreFingerprintStore, StoreFingerprintChain, FakeStoreFingerprintAlarmSink, xUnit
// Extends: Add a case here for every new way the chain can be damaged.

using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class StoreFingerprintChainStoreTests : IDisposable
{
	private readonly string _root;
	private readonly string _fingerprintPath;
	private readonly string _anomalyMarkerPath;
	private readonly string _chainDirectory;
	private readonly string _tipPath;
	private readonly InMemorySecretProtector _protector = new();
	private readonly FakeStoreFingerprintAlarmSink _sink = new();

	public StoreFingerprintChainStoreTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-fpchain-" + Guid.NewGuid().ToString("N"));
		_fingerprintPath = Path.Combine(_root, "integrity", RdpAuditPaths.StoreFingerprintFileName);
		_anomalyMarkerPath = Path.Combine(_root, "integrity", RdpAuditPaths.StoreIntegrityAnomalyMarkerFileName);
		_chainDirectory = Path.Combine(_root, "integrity", RdpAuditPaths.StoreFingerprintChainFolderName);
		_tipPath = Path.Combine(_root, "integrity", RdpAuditPaths.StoreFingerprintSealedTipFileName);
	}

	public void Dispose()
	{
		try
		{
			if (Directory.Exists(_root))
			{
				Directory.Delete(_root, recursive: true);
			}
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── Happy path ───────────────────────────────────────────────────────────────

	[Fact]
	public void Write_AppendsAChainEntryAndSealsTheTip()
	{
		StoreFingerprintStore store = CreateStore();

		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.Equal(2, verification.EntryCount);
		Assert.Equal(2, Directory.GetFiles(_chainDirectory, "fingerprint-*.json").Length);
		Assert.True(File.Exists(_tipPath));

		// The tip is a protected envelope, not readable JSON: that is the point of the second store.
		string tipText = File.ReadAllText(_tipPath);
		Assert.True(_protector.IsProtectedEnvelope(tipText));
		Assert.DoesNotContain("EntryCount", tipText, StringComparison.Ordinal);

		// The read shape the comparer and the overview use still resolves both baselines.
		StoreFingerprintDocument document = store.Read();
		Assert.Equal("Shutdown", document.LastCleanShutdown!.CapturedBy);
		Assert.Equal("Schedule", document.LastPeriodic!.CapturedBy);
	}

	[Fact]
	public void Write_OnAFreshStore_LeavesAnAnomalyFreeChain()
	{
		StoreFingerprintStore store = CreateStore();

		Assert.Equal(StoreFingerprintChainState.Ok, store.ReadAndVerify().State);

		store.Write(Fingerprint("Schedule", clean: false, rows: 1), cleanShutdown: false);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();
		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.Empty(verification.Findings);
	}

	// ── Deletion of the newest entry (the case the pre-B19 layout could not see) ─

	[Fact]
	public void DeletingTheNewestEntry_IsReportedAsMissing_NotAsNoData()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);
		store.Write(Fingerprint("Schedule", clean: false, rows: 14), cleanShutdown: false);

		File.Delete(Path.Combine(_chainDirectory, "fingerprint-0000000003.json"));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Missing, verification.Message);
		Assert.Equal(2, verification.EntryCount);
		Assert.Contains("DELETED", verification.Message, StringComparison.Ordinal);
		Assert.Equal("Missing", _sink.Published[^1].State);
	}

	[Fact]
	public void DeletingTheWholeChainDirectory_IsReportedAsMissing()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		Directory.Delete(_chainDirectory, recursive: true);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Missing, verification.Message);
		Assert.Equal(0, verification.EntryCount);
	}

	// ── Editing / reordering ─────────────────────────────────────────────────────

	[Fact]
	public void EditingAnEntryPayload_IsReportedAsChainBroken()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 20), cleanShutdown: false);

		string path = Path.Combine(_chainDirectory, "fingerprint-0000000002.json");
		string json = File.ReadAllText(path);
		using (JsonDocument document = JsonDocument.Parse(json))
		{
			// Lower the recorded row count in place, leaving the stored digest untouched: the "make the store
			// look untouched" edit that the pre-B19 fingerprint could not detect at all.
			string edited = json.Replace("\"RawEvents\": 20", "\"RawEvents\": 2", StringComparison.Ordinal);
			Assert.NotEqual(json, edited);
			File.WriteAllText(path, edited);
		}

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.ChainBroken, verification.Message);
		Assert.Contains(verification.Findings, finding => finding.Contains("does not match its own digest", StringComparison.Ordinal));
		Assert.Equal("ChainBroken", _sink.Published[^1].State);
	}

	[Fact]
	public void DeletingAMiddleEntry_IsReportedAsChainBroken()
	{
		StoreFingerprintStore store = CreateStore();
		for (int index = 1; index <= 3; index++)
		{
			store.Write(Fingerprint("Schedule", clean: false, rows: index * 10), cleanShutdown: false);
		}

		File.Delete(Path.Combine(_chainDirectory, "fingerprint-0000000002.json"));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		Assert.Contains(verification.Findings, finding => finding.Contains("does not link to its predecessor", StringComparison.Ordinal));
	}

	[Fact]
	public void AnUnparsableEntryFile_IsReportedAsUnreadable()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		File.WriteAllText(Path.Combine(_chainDirectory, "fingerprint-0000000002.json"), "{ this is not json");

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.Equal(StoreFingerprintChainState.Unreadable, verification.State);
		Assert.Equal("Unreadable", _sink.Published[^1].State);
	}

	// ── The sealed tip ───────────────────────────────────────────────────────────

	/// <summary>A truncated envelope - the payload cut in half - unseals into a half-written record, so the tip
	/// cannot be read and the state is Unreadable. The damage is done to the CIPHER BYTES, not to whichever
	/// base64 character happens to sit in the middle of the file: which character that is depends on the length
	/// of the tip's timestamp, so an edit by position lands in the digest, in a property name, or in a base64
	/// bit that carries no payload at all - different verdicts from one test, which is how this case used to fail
	/// one run in two. Truncation has exactly one outcome, and this test pins that one.</summary>
	[Fact]
	public void TruncatingTheSealedTipEnvelope_MakesItUnreadable()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		string tipText = File.ReadAllText(_tipPath);
		byte[] cipher = Convert.FromBase64String(ExtractPayload(tipText));
		File.WriteAllText(
			_tipPath,
			tipText.Replace(
				ExtractPayload(tipText),
				Convert.ToBase64String(cipher.AsSpan(0, cipher.Length / 2).ToArray()),
				StringComparison.Ordinal));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Unreadable, verification.Message);
		Assert.Contains(verification.Findings, finding => finding.Contains("sealed fingerprint tip", StringComparison.Ordinal));
		Assert.Equal("Unreadable", _sink.Published[^1].State);
	}

	/// <summary>The other honest outcome of "the tip file was edited by hand", pinned instead of left to luck:
	/// damage that cannot change a single cipher byte. The final base64 character of the payload carries bits
	/// that no decoded byte uses, and the edit below is confined to them, so every protector - DPAPI included -
	/// still unseals the tip that was sealed, and the tip still records the same length and the same head. The
	/// verdict for a tip that is byte-identical from the store's point of view is Ok with no findings; reporting
	/// tampering here would be a false alarm, and one that a shortened digest could not even show. The record is
	/// padded to a length where those unused bits exist, because a payload whose byte count is a multiple of
	/// three has none - a property of base64, not a guess about this run.</summary>
	[Fact]
	public void EditingBitsThatCarryNoPayload_LeavesTheChainOk()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		string tipText = File.ReadAllText(_tipPath);
		StoreFingerprintChainVerification before = store.ReadAndVerify();
		StoreFingerprintSealedTip sealedTip = before.SealedTip!;

		// Re-seal the SAME record, padded until the cipher has bytes left over, then edit only the bits the last
		// base64 character does not contribute to any of them.
		byte[] cipher;
		string envelope;
		int padding = 0;
		do
		{
			envelope = _protector.Protect(JsonSerializer.Serialize(sealedTip) + new string(' ', padding));
			cipher = Convert.FromBase64String(ExtractPayload(envelope));
			padding++;
		}
		while (cipher.Length % 3 == 0);

		string damaged = FlipUnusedBase64Bits(envelope);
		Assert.NotEqual(envelope, damaged);
		Assert.Equal(cipher, Convert.FromBase64String(ExtractPayload(damaged)));

		File.WriteAllText(
			_tipPath,
			tipText.Replace(ExtractPayload(tipText), ExtractPayload(damaged), StringComparison.Ordinal));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Ok, verification.Message);
		Assert.Empty(verification.Findings);
		Assert.Equal(before.EntryCount, verification.EntryCount);
		Assert.Equal(sealedTip.HeadDigest, verification.SealedTip!.HeadDigest);
	}

	/// <summary>A tip whose <c>EntryCount</c> property is gone is a tip whose LENGTH could not be read, not a tip
	/// claiming a shorter chain. The number used to fall back to its default zero, and the store then announced
	/// "the sealed tip records 0 entr(ies)" and called a chain that had not moved "rolled back", while printing
	/// the tip's head and the chain's head as the same value - a substitution alarm raised by a file whose head
	/// was never touched. The verdict is Unreadable: we could not read the tip, so the chain's length is
	/// UNVERIFIED.</summary>
	[Fact]
	public void ASealedTipWithoutItsEntryCount_IsReportedAsUnreadable_NotAsARollback()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		string tipText = File.ReadAllText(_tipPath);
		JsonObject tipRecord = JsonNode.Parse(_protector.Unprotect(tipText))!.AsObject();
		Assert.True(tipRecord.Remove("EntryCount"), "The sealed tip no longer carries an EntryCount property.");

		// Still a protected envelope the store can unseal: only the property is gone, which is what an edit to the
		// second store looks like when the editor can re-seal it.
		File.WriteAllText(
			_tipPath,
			tipText.Replace(
				ExtractPayload(tipText),
				ExtractPayload(_protector.Protect(tipRecord.ToJsonString())),
				StringComparison.Ordinal));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Unreadable, verification.Message);
		Assert.Contains(verification.Findings, finding => finding.Contains("sealed fingerprint tip", StringComparison.Ordinal));
		Assert.DoesNotContain(verification.Findings, finding => finding.Contains("rolled back", StringComparison.Ordinal));
		Assert.DoesNotContain("0 entr(ies)", verification.Message, StringComparison.Ordinal);
	}

	/// <summary>The same rule on the chain side, where the property that disappears is <c>Sequence</c>. It used to
	/// default to zero, and the store answered "Entry 0 is out of place ... so an entry was removed or renumbered"
	/// - an accusation of a removal over a file that was not removed from anything. An entry file that does not
	/// carry the fields this build always writes is one we could not read, and it is reported as such whichever
	/// field is missing; the tip still accounts for an entry that is no longer on disk, so the state is Missing.
	/// </summary>
	[Fact]
	public void AChainEntryWithoutItsSequenceField_IsReportedAsMissing_NotAsARemoval()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		string path = Path.Combine(_chainDirectory, "fingerprint-0000000001.json");
		JsonObject entry = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
		Assert.True(entry.Remove("Sequence"), "The chain entry no longer carries a Sequence property.");
		File.WriteAllText(path, entry.ToJsonString());

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Missing, verification.Message);
		Assert.Equal(0, verification.EntryCount);
		Assert.Contains(verification.Findings, finding => finding.Contains("could not be read", StringComparison.Ordinal));
		Assert.DoesNotContain(verification.Findings, finding => finding.Contains("removed or renumbered", StringComparison.Ordinal));
	}

	/// <summary>A third edit the tip file can carry, recorded so its verdict is a decision rather than luck: the
	/// verification compares the tip's LENGTH and its HEAD, so rewriting the sealing time the tip reports leaves
	/// the state Ok, and this test says so instead of implying that every edit to the second store is caught here.
	/// The bytes of the tip are defended one layer up - a DPAPI envelope stops unsealing after any byte was
	/// changed, which is why the tip is written through ISecretProtector and why TipIsProtected reports when it
	/// could not be - while the tip's own fields are covered only where the chain can contradict them.</summary>
	[Fact]
	public void EditingTheSealingTimeTheTipReports_LeavesTheChainOk()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		string tipText = File.ReadAllText(_tipPath);
		StoreFingerprintChainVerification before = store.ReadAndVerify();
		JsonObject tipRecord = JsonNode.Parse(_protector.Unprotect(tipText))!.AsObject();
		DateTime original = tipRecord["SealedUtc"]!.GetValue<DateTime>();
		tipRecord["SealedUtc"] = original.AddMinutes(1);
		Assert.NotEqual(original, tipRecord["SealedUtc"]!.GetValue<DateTime>());

		File.WriteAllText(
			_tipPath,
			tipText.Replace(
				ExtractPayload(tipText),
				ExtractPayload(_protector.Protect(tipRecord.ToJsonString())),
				StringComparison.Ordinal));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Ok, verification.Message);
		Assert.Empty(verification.Findings);
		Assert.Equal(before.EntryCount, verification.EntryCount);
		Assert.Equal(before.SealedTip!.HeadDigest, verification.SealedTip!.HeadDigest);
		Assert.Equal(original.AddMinutes(1), verification.SealedTip.SealedUtc);
	}

	[Fact]
	public void ReplacingTheSealedTipWithPlaintext_MakesItUnreadable()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		// A hand-written tip that claims the chain is complete: accepted only if it were ALSO protected, which
		// an attacker who can only write files cannot arrange for the DPAPI key of the service account.
		File.WriteAllText(
			_tipPath,
			JsonSerializer.Serialize(new StoreFingerprintSealedTip
			{
				EntryCount = 1,
				HeadDigest = new string('d', 64),
				HeadSequence = 1,
				SealedUtc = DateTime.UtcNow,
			}));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Unreadable, verification.Message);
		Assert.Contains(verification.Findings, finding => finding.Contains("NOT a protected envelope", StringComparison.Ordinal));
	}

	/// <summary>The honest limit, asserted so it cannot be misread as a guarantee: with the tip GONE and the
	/// chain intact the chain still verifies, because an absent second store cannot contradict anything. The
	/// test records that the state is Ok in that case rather than pretending it is detectable.</summary>
	[Fact]
	public void DeletingTheSealedTipAlongWithTheTail_LeavesTheRemainingChainOk()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 20), cleanShutdown: false);

		File.Delete(_tipPath);
		File.Delete(Path.Combine(_chainDirectory, "fingerprint-0000000002.json"));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		// Documented limitation: removing BOTH stores leaves a shorter but self-consistent chain. It is why the
		// second store is mirrored outside the integrity folder when the event-log source exists, and why
		// nothing in this feature claims the deletion is impossible - only that leaving one store behind makes
		// it visible.
		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.Equal(1, verification.EntryCount);
		Assert.True(store.TipIsProtected);
	}

	// ── Migration from the pre-B19 document ──────────────────────────────────────

	[Fact]
	public void APreB19Document_IsMigratedIntoTheChainOnce_AndKeepsBothBaselines()
	{
		Directory.CreateDirectory(Path.GetDirectoryName(_fingerprintPath)!);
		StoreFingerprintDocument legacy = new()
		{
			LastCleanShutdown = Fingerprint("Shutdown", clean: true, rows: 5),
			LastPeriodic = Fingerprint("Schedule", clean: false, rows: 6),
		};
		File.WriteAllText(_fingerprintPath, JsonSerializer.Serialize(legacy, new JsonSerializerOptions { WriteIndented = true }));

		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Schedule", clean: false, rows: 7), cleanShutdown: false);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.Equal(3, verification.EntryCount);
		Assert.Equal("Shutdown", verification.LastCleanShutdown!.Fingerprint.CapturedBy);
		Assert.Equal(5L, verification.LastCleanShutdown.Fingerprint.TableRowCounts["RawEvents"]);

		// The legacy file is history, not a live slot: a second write must not migrate it again.
		store.Write(Fingerprint("Schedule", clean: false, rows: 8), cleanShutdown: false);
		Assert.Equal(4, store.ReadAndVerify().EntryCount);
		Assert.True(File.Exists(_fingerprintPath));
	}

	[Fact]
	public void AnUnreadablePreB19Document_MigratesNothing()
	{
		Directory.CreateDirectory(Path.GetDirectoryName(_fingerprintPath)!);
		File.WriteAllText(_fingerprintPath, "{ not json");

		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Schedule", clean: false, rows: 7), cleanShutdown: false);

		// No baseline is fabricated from a document that could not be read.
		StoreFingerprintChainVerification verification = store.ReadAndVerify();
		Assert.Equal(1, verification.EntryCount);
		Assert.Null(verification.LastCleanShutdown);
	}

	/// <summary>B22 on the migration path: a pre-B19 slot that carries an explicit <c>null</c> in a field this
	/// layout always writes is a slot that could not be read faithfully, so it is NOT migrated. Migrating it
	/// would write a chain entry the reader then refuses - and because the sealed tip would account for it, the
	/// chain would report <c>Missing</c> for the rest of the installation's life: a permanent false deletion
	/// alarm produced by one damaged field. The read path must also survive computing a digest over it, which is
	/// what used to throw <c>NullReferenceException</c> out of the write entirely.</summary>
	[Fact]
	public void APreB19SlotWithANullCollection_IsNotMigrated_AndDoesNotThrow()
	{
		Directory.CreateDirectory(Path.GetDirectoryName(_fingerprintPath)!);
		string document = JsonSerializer.Serialize(new StoreFingerprintDocument
		{
			LastCleanShutdown = Fingerprint("Shutdown", clean: true, rows: 5),
		});
		File.WriteAllText(_fingerprintPath, WithExplicitNull(document, "LastCleanShutdown.AppliedMigrations"));

		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Schedule", clean: false, rows: 7), cleanShutdown: false);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Ok, verification.Message);
		Assert.Equal(1, verification.EntryCount);
		Assert.Null(verification.LastCleanShutdown);
	}

	// ── The mirror sink and the tip's protection ─────────────────────────────────

	[Fact]
	public void ACleanShutdown_PublishesTheTipToTheMirrorSink()
	{
		StoreFingerprintStore store = CreateStore();

		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		StoreFingerprintAlarm alarm = Assert.Single(_sink.Published);
		Assert.Equal("CleanShutdownTip", alarm.Kind);
		Assert.Equal(1, alarm.EntryCount);
		Assert.Equal(new string('0', 64), StoreFingerprintChain.GenesisDigest);
		Assert.NotEqual(StoreFingerprintChain.GenesisDigest, alarm.HeadDigest);

		// A periodic capture is NOT mirrored: the Application log must not grow with every maintenance pass.
		store.Write(Fingerprint("Schedule", clean: false, rows: 11), cleanShutdown: false);
		Assert.Single(_sink.Published);
	}

	[Fact]
	public void AStoreWithoutAProtector_SaysSoInsteadOfImplyingTheTipIsSealed()
	{
		StoreFingerprintStore unsealed = new(
			_fingerprintPath,
			_anomalyMarkerPath,
			NullLogger<StoreFingerprintStore>.Instance);

		unsealed.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		Assert.False(unsealed.TipIsProtected);
		Assert.Equal(StoreFingerprintChainState.Ok, unsealed.ReadAndVerify().State);

		// With no protector configured, plaintext is the expected form and must NOT be reported as tampering.
		// The limitation is exposed through TipIsProtected instead - which the Configurator-visible overview
		// does not have to guess about.
		Assert.Contains("EntryCount", File.ReadAllText(_tipPath), StringComparison.Ordinal);
	}

	[Fact]
	public void AMissingMirrorSink_IsReportedAsUnavailableWithAReason()
	{
		// The 3-arg constructor is the "no opener configured" host: no protector, no sink.
		StoreFingerprintStore store = new(
			_fingerprintPath,
			_anomalyMarkerPath,
			NullLogger<StoreFingerprintStore>.Instance);

		Assert.False(store.AlarmMirrorAvailable);
		Assert.False(string.IsNullOrWhiteSpace(store.AlarmMirrorUnavailableReason));
		Assert.False(store.TipIsProtected);
	}

	// ── The interrupted write (B24) ──────────────────────────────────────────────

	/// <summary>A capture that fails between appending its chain entry and re-sealing the tip. The failure is
	/// injected where the process would die - after the entry is durably on disk, at the tip write - by making
	/// the tip path un-writable, which is the same state a crash leaves and needs no test-only hook inside the
	/// production writer: the intent IS on disk by then, because it is written first.
	/// <para>
	/// The verdict is <c>Interrupted</c>, not the "rolled back or replaced" alarm the same on-disk shape
	/// produced before B24, and it reaches the operator through the ordinary signals - a finding, a message and
	/// the mirror sink - because a state nobody can see is not a fix.
	/// </para>
	/// </summary>
	[Fact]
	public void ACaptureInterruptedBetweenTheEntryAndTheTip_IsReportedAsInterrupted_NotAsTampering()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);

		InterruptTheTipWrite();

		// The failure is swallowed by design (a lost fingerprint is never a correctness problem), so the test
		// observes the store, not the exception.
		store.Write(Fingerprint("Schedule", clean: false, rows: 14), cleanShutdown: false);

		// The write got as far as the new entry, and the intent that describes it survived.
		Assert.Equal(3, Directory.GetFiles(_chainDirectory, "fingerprint-*.json").Length);
		Assert.True(File.Exists(store.WriteIntentPath), "The interrupted write left no intent behind.");

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Interrupted, verification.Message);
		Assert.Equal(3, verification.EntryCount);

		// Visible, with an honest sentence: the finding names the entry the intent declared, and the message
		// says what happened and what happens next instead of accusing the store of being replaced.
		string finding = Assert.Single(verification.Findings);
		Assert.Contains("durable write intent", finding, StringComparison.Ordinal);
		Assert.Contains("interrupted", verification.Message, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("re-sealing the tip over the full chain", verification.Message, StringComparison.Ordinal);
		Assert.DoesNotContain("OLDER chain", verification.Message, StringComparison.Ordinal);

		// Same signalling path as every other non-Ok state.
		Assert.Equal("Interrupted", _sink.Published[^1].State);
		Assert.True(verification.IsAlarming);
	}

	/// <summary>The property that keeps the recoverable state honest, asserted at the file level: delete the
	/// intent and the IDENTICAL discrepancy is the strict verdict again. An attacker cannot earn the softer
	/// state by removing a file - the file is the evidence, so removing it takes the reading away.
	/// </summary>
	[Fact]
	public void DeletingTheWriteIntent_LeavesTheSameDiscrepancyStrict()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);
		InterruptTheTipWrite();
		store.Write(Fingerprint("Schedule", clean: false, rows: 14), cleanShutdown: false);

		Assert.Equal(StoreFingerprintChainState.Interrupted, store.ReadAndVerify().State);

		File.Delete(store.WriteIntentPath);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.ChainBroken, verification.Message);
		Assert.Contains("OLDER chain", verification.Message, StringComparison.Ordinal);
	}

	/// <summary>An intent that does not match what is on disk - here a different digest - explains nothing, so
	/// the same discrepancy stays strict. A hand-written intent is not a licence.</summary>
	[Fact]
	public void AWriteIntentThatNamesADifferentEntry_IsIgnored()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);
		InterruptTheTipWrite();
		store.Write(Fingerprint("Schedule", clean: false, rows: 14), cleanShutdown: false);

		string text = File.ReadAllText(store.WriteIntentPath);
		StoreFingerprintWriteIntent intent = JsonSerializer.Deserialize<StoreFingerprintWriteIntent>(
			_protector.Unprotect(text))!;
		File.WriteAllText(
			store.WriteIntentPath,
			_protector.Protect(JsonSerializer.Serialize(intent with { ExpectedHeadDigest = new string('a', 64) })));

		Assert.Equal(StoreFingerprintChainState.ChainBroken, store.ReadAndVerify().State);
	}

	/// <summary>An intent in plain text on a host that seals them is not an intent this build wrote, so it is
	/// not usable and the strict verdict stands. Fail-closed: an unverifiable claim cannot soften a verdict.</summary>
	[Fact]
	public void AWriteIntentThatIsNotASealedEnvelope_IsIgnored()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);
		InterruptTheTipWrite();
		store.Write(Fingerprint("Schedule", clean: false, rows: 14), cleanShutdown: false);

		File.WriteAllText(
			store.WriteIntentPath,
			JsonSerializer.Serialize(new StoreFingerprintWriteIntent
			{
				ExpectedEntryCount = 3,
				ExpectedHeadSequence = 3,
				ExpectedHeadDigest = JsonSerializer.Deserialize<StoreFingerprintChainEntry>(
					File.ReadAllText(Path.Combine(_chainDirectory, "fingerprint-0000000003.json")))!.Digest,
			}));

		Assert.Equal(StoreFingerprintChainState.ChainBroken, store.ReadAndVerify().State);
	}

	/// <summary>The strongest form of "this does not weaken detection", on the real files: with a PERFECT
	/// intent on disk - every field matching the appended entry - an edit to an entry that was already sealed is
	/// still reported. The intent can explain an append; it cannot explain a substitution.</summary>
	[Fact]
	public void AnEditedEntry_IsStillReported_EvenWithAPerfectIntentOnDisk()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);
		InterruptTheTipWrite();
		store.Write(Fingerprint("Schedule", clean: false, rows: 14), cleanShutdown: false);

		string path = Path.Combine(_chainDirectory, "fingerprint-0000000001.json");
		string json = File.ReadAllText(path);
		string edited = json.Replace("\"RawEvents\": 10", "\"RawEvents\": 3", StringComparison.Ordinal);
		Assert.NotEqual(json, edited);
		File.WriteAllText(path, edited);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.Equal(StoreFingerprintChainState.ChainBroken, verification.State);
		Assert.Contains(verification.Findings, item => item.Contains("does not match its own digest", StringComparison.Ordinal));
	}

	/// <summary>The next successful capture repairs the store on its own: it re-seals the tip over every entry
	/// on disk, so the interrupted state clears without an operator doing anything, and without a special
	/// "repair" path that could itself be wrong.</summary>
	[Fact]
	public void TheNextSuccessfulWrite_RepairsAnInterruptedStore()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);
		InterruptTheTipWrite();
		store.Write(Fingerprint("Schedule", clean: false, rows: 14), cleanShutdown: false);
		Assert.Equal(StoreFingerprintChainState.Interrupted, store.ReadAndVerify().State);

		// The transient I/O problem is gone; the operator does nothing but let the service capture again.
		RestoreTheTipPath();
		store.Write(Fingerprint("Schedule", clean: false, rows: 16), cleanShutdown: false);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Ok, verification.Message);
		Assert.Equal(4, verification.EntryCount);
		Assert.Empty(verification.Findings);
		Assert.False(File.Exists(store.WriteIntentPath), "A completed write left its intent behind.");

		// The entry that the interrupted write had appended is still part of the chain: self-healing re-seals
		// the tip over it, it does not discard it - and the repair needed nothing from the operator.
		Assert.True(File.Exists(Path.Combine(_chainDirectory, "fingerprint-0000000003.json")));
		Assert.Equal(4, verification.SealedTip!.EntryCount);
	}

	/// <summary>The marker is part of a write in flight, not a permanent artifact: a store that captured
	/// normally has no intent left, so the file's absence cannot be mistaken for a limitation.</summary>
	[Fact]
	public void ACompletedWrite_LeavesNoWriteIntentBehind()
	{
		StoreFingerprintStore store = CreateStore();

		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		Assert.False(File.Exists(store.WriteIntentPath));
		Assert.Equal(StoreFingerprintChainState.Ok, store.ReadAndVerify().State);
	}

	/// <summary>Compatibility: a chain and a tip written by the build that had no write intent at all (there is
	/// simply no marker next to them) verify exactly as before - Ok, no findings. The new artifact is additive,
	/// and its absence means "no interrupted write", not "unverified".</summary>
	[Fact]
	public void AStoreWrittenWithoutAWriteIntent_VerifiesAsBefore()
	{
		StoreFingerprintStore store = CreateStore();
		Directory.CreateDirectory(_chainDirectory);

		List<StoreFingerprintChainEntry> entries = [];
		foreach (long rows in new long[] { 10, 12 })
		{
			StoreFingerprintChainEntry entry = new()
			{
				Sequence = entries.Count + 1,
				CapturedUtc = DateTime.UtcNow,
				CleanShutdown = rows == 10,
				CapturedBy = rows == 10 ? "Shutdown" : "Schedule",
				PreviousDigest = entries.Count > 0 ? entries[^1].Digest : StoreFingerprintChain.GenesisDigest,
				Fingerprint = Fingerprint(rows == 10 ? "Shutdown" : "Schedule", clean: rows == 10, rows: rows),
			};
			entry = entry with { Digest = StoreFingerprintChain.ComputeDigest(entry) };
			File.WriteAllText(
				Path.Combine(_chainDirectory, "fingerprint-" + entry.Sequence.ToString("D10") + ".json"),
				JsonSerializer.Serialize(entry, new JsonSerializerOptions { WriteIndented = true }));
			entries.Add(entry);
		}

		File.WriteAllText(
			_tipPath,
			_protector.Protect(JsonSerializer.Serialize(StoreFingerprintChain.Seal(entries))));

		Assert.False(File.Exists(store.WriteIntentPath));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Ok, verification.Message);
		Assert.Equal(2, verification.EntryCount);
		Assert.Empty(verification.Findings);
	}

	// ── B23: the tip's layout version is compared, not assumed ───────────────────

	/// <summary>The tip of this layout still reads: the version check is a comparison, not a rejection of what
	/// is already on disk.</summary>
	[Fact]
	public void ASealedTipOfTheCurrentLayoutVersion_IsStillRead()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.Equal(StoreFingerprintChainState.Ok, verification.State);
		Assert.Equal(StoreFingerprintSealedTip.CurrentFormatVersion, verification.SealedTip!.FormatVersion);
	}

	/// <summary>The other branch: a tip written in a layout this build does not read is reported as unreadable
	/// instead of being interpreted field by field under this one's rules - the same treatment a chain entry of
	/// an unknown version already gets. "We could not read the tip" keeps the chain's length UNVERIFIED, which
	/// is a loud state, not a confirmation.</summary>
	[Fact]
	public void ASealedTipOfAnotherLayoutVersion_IsUnreadable_NotSilentlyAccepted()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		string tipText = File.ReadAllText(_tipPath);
		StoreFingerprintSealedTip tip = JsonSerializer.Deserialize<StoreFingerprintSealedTip>(
			_protector.Unprotect(tipText))!;
		File.WriteAllText(
			_tipPath,
			tipText.Replace(
				ExtractPayload(tipText),
				ExtractPayload(_protector.Protect(
					JsonSerializer.Serialize(tip with { FormatVersion = StoreFingerprintSealedTip.CurrentFormatVersion + 1 }))),
				StringComparison.Ordinal));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Unreadable, verification.Message);
		Assert.Contains(verification.Findings, item => item.Contains("layout version", StringComparison.Ordinal));
		Assert.False(verification.TipReadable);
	}

	/// <summary>The tip's HeadSequence is cross-checked against the entry it names, so a second store whose own
	/// two fields disagree with the chain is reported. Before B23 this field was read and never compared, so a
	/// tip claiming sequence 99 over a three-entry chain verified as Ok.</summary>
	[Fact]
	public void ASealedTipWhoseHeadSequenceWasReplaced_IsChainBroken()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);

		string tipText = File.ReadAllText(_tipPath);
		StoreFingerprintSealedTip tip = JsonSerializer.Deserialize<StoreFingerprintSealedTip>(
			_protector.Unprotect(tipText))!;
		File.WriteAllText(
			_tipPath,
			tipText.Replace(
				ExtractPayload(tipText),
				ExtractPayload(_protector.Protect(
					JsonSerializer.Serialize(tip with { HeadSequence = tip.HeadSequence + 40 }))),
				StringComparison.Ordinal));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.ChainBroken, verification.Message);
		Assert.Contains(verification.Findings, item => item.Contains("chain sequence", StringComparison.Ordinal));
	}

	// ── B22: a null in a field this layout always writes is not a crash ──────────

	/// <summary>Every collection- and object-valued field on the canonicalisation path, set to an EXPLICIT
	/// <c>null</c> in the file: the read must answer with a verdict that names the field instead of throwing
	/// <c>NullReferenceException</c> out of the store's "never throws" contract. The verdict is not asserted to
	/// be one particular state - an entry the reader cannot use changes what the chain looks like, and the
	/// resulting state depends on which entry was damaged - but it is never <c>Ok</c>, never silent, and never a
	/// crash.</summary>
	[Theory]
	[InlineData("Fingerprint.TableRowCounts")]
	[InlineData("Fingerprint.AppliedMigrations")]
	[InlineData("Fingerprint")]
	[InlineData("Fingerprint.LedgerChainHead")]
	[InlineData("Fingerprint.CapturedBy")]
	[InlineData("PreviousDigest")]
	[InlineData("CapturedBy")]
	[InlineData("Digest")]
	public void AnExplicitNullInAFieldThisLayoutAlwaysWrites_IsReported_NotThrown(string propertyPath)
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
		store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);

		string path = Path.Combine(_chainDirectory, "fingerprint-0000000001.json");
		File.WriteAllText(path, WithExplicitNull(File.ReadAllText(path), propertyPath));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.NotEqual(StoreFingerprintChainState.Ok, verification.State);

		// The field is NAMED, which is the difference between an actionable finding and a crash: the entry is
		// reported as one whose null-bearing field could not be read, not as an edited one and not as a
		// NullReferenceException.
		string fieldName = propertyPath.Split('.')[^1];
		Assert.Contains(verification.Findings, item => item.Contains(fieldName, StringComparison.Ordinal));
		Assert.DoesNotContain(verification.Findings, item => item.Contains("NullReference", StringComparison.Ordinal));
	}

	/// <summary>The tip side of the same rule: a tip whose head digest is <c>null</c> is one we could not read,
	/// and the state says so rather than printing a digest nobody recorded.</summary>
	[Fact]
	public void ASealedTipWithANullHeadDigest_IsUnreadable()
	{
		StoreFingerprintStore store = CreateStore();
		store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);

		string tipText = File.ReadAllText(_tipPath);
		JsonObject tip = JsonNode.Parse(_protector.Unprotect(tipText))!.AsObject();
		tip["HeadDigest"] = null;
		File.WriteAllText(
			_tipPath,
			tipText.Replace(
				ExtractPayload(tipText),
				ExtractPayload(_protector.Protect(tip.ToJsonString())),
				StringComparison.Ordinal));

		StoreFingerprintChainVerification verification = store.ReadAndVerify();

		Assert.True(verification.State == StoreFingerprintChainState.Unreadable, verification.Message);
		Assert.False(verification.TipReadable);
	}

	/// <summary>The acceptance criterion for B22 in one place: whatever a file says - an explicit null, a wrong
	/// type, an absurd number, an empty collection, a removed property - reading it produces a verdict and never
	/// an exception, and never <c>Ok</c> for content that moved under the digest.</summary>
	[Fact]
	public void ReadAndVerify_NeverThrows_ForAnyMutationOfAValidEntryFile()
	{
		string[] propertyPaths =
		[
			"FormatVersion",
			"Sequence",
			"CapturedUtc",
			"CleanShutdown",
			"CapturedBy",
			"PreviousDigest",
			"Digest",
			"Fingerprint",
			"Fingerprint.FormatVersion",
			"Fingerprint.CapturedUtc",
			"Fingerprint.CleanShutdown",
			"Fingerprint.CapturedBy",
			"Fingerprint.DatabaseBytes",
			"Fingerprint.WalBytes",
			"Fingerprint.DatabaseLastWriteUtc",
			"Fingerprint.LastIngestionSequence",
			"Fingerprint.TableRowCounts",
			"Fingerprint.AppliedMigrations",
			"Fingerprint.LedgerChainedRows",
			"Fingerprint.LedgerUnchainedRows",
			"Fingerprint.LedgerChainHead",
			"Fingerprint.LedgerChainIntact",
		];
		JsonNode[] mutations =
		[
			JsonValue.Create("not the type this field is")!,
			JsonValue.Create(9_999_999_999_999_999L)!,
			JsonValue.Create(-9_999_999_999_999_999L)!,
			new JsonArray(),
			new JsonObject(),
			JsonValue.Create(string.Empty)!,
		];

		int cases = 0;
		foreach (string propertyPath in propertyPaths)
		{
			cases++;
			AssertMutationIsAVerdict(original => WithExplicitNull(original, propertyPath), propertyPath + " = null");

			foreach (JsonNode mutation in mutations)
			{
				cases++;
				AssertMutationIsAVerdict(
					original => WithJsonValue(original, propertyPath, mutation),
					propertyPath + " = " + mutation.ToJsonString());
			}

			// Removing a field is invisible to the digest exactly when the value on disk IS that field's default:
			// the deserializer puts the same default back and the canonical text never moves. That is arithmetic,
			// not a gap - these fields are written at their default value by the fixture below, and the loop
			// therefore does not pretend their removal must change a verdict. The loop still exercises every OTHER
			// field's removal, and the list itself is asserted by a test of its own.
			if (RemovalsThatCannotMoveTheDigest.Contains(propertyPath))
			{
				continue;
			}

			cases++;
			AssertMutationIsAVerdict(original => RemoveJson(original, propertyPath), propertyPath + " removed");
		}

		Assert.Equal(
			(propertyPaths.Length * (mutations.Length + 2)) - RemovalsThatCannotMoveTheDigest.Length,
			cases);
	}

	/// <summary>Fields this fixture writes at their default value, so removing the property from the file leaves
	/// the value the reader reconstructs unchanged: the payload's own <c>FormatVersion</c> is the current layout
	/// version, the ledger's chained/unchained row counts are zero for a store whose ledger is empty, the ledger
	/// chain head is the genesis value, and the ledger chain intact flag is true. Named here, asserted below, so
	/// that "removing this field is invisible" is a statement someone checked rather than a gap someone left.</summary>
	private static readonly string[] RemovalsThatCannotMoveTheDigest =
	[
		"Fingerprint.FormatVersion",
		"Fingerprint.LedgerChainedRows",
		"Fingerprint.LedgerUnchainedRows",
		"Fingerprint.LedgerChainHead",
		"Fingerprint.LedgerChainIntact",
	];

	/// <summary>The other half of the fuzz loop's contract, made explicit: for each field that carries its default
	/// value, deleting the property is a no-op and the store still verifies - the value is restored, not invented,
	/// and nothing about it was hidden by the removal.</summary>
	[Fact]
	public void RemovingAFieldThatCarriesItsDefaultValue_CannotMoveTheDigest()
	{
		foreach (string propertyPath in RemovalsThatCannotMoveTheDigest)
		{
			WithFreshStore((store, chainDirectory) =>
			{
				string path = Path.Combine(chainDirectory, "fingerprint-0000000001.json");
				string original = File.ReadAllText(path);
				string removed = RemoveJson(original, propertyPath);
				Assert.NotEqual(Normalize(original), Normalize(removed));
				File.WriteAllText(path, removed);

				StoreFingerprintChainVerification verification = store.ReadAndVerify();

				Assert.True(verification.State == StoreFingerprintChainState.Ok, propertyPath + ": " + verification.Message);
				Assert.Empty(verification.Findings);
			});
		}
	}

	/// <summary>Applies one mutation to a fresh two-entry store of its own, then asserts the read path answered
	/// instead of throwing and that content which actually moved is never reported as <c>Ok</c> - the digest
	/// covers every field of an entry, so a change must move the verdict with it. "Actually moved" is compared
	/// on the parsed form rather than the file bytes, so re-indenting cannot be mistaken for a mutation.</summary>
	private void AssertMutationIsAVerdict(Func<string, string> mutate, string label)
		=> WithFreshStore((store, chainDirectory) =>
		{
			string path = Path.Combine(chainDirectory, "fingerprint-0000000001.json");
			string original = File.ReadAllText(path);
			string mutated = mutate(original);
			Assert.NotEqual(Normalize(original), Normalize(mutated));
			File.WriteAllText(path, mutated);

			StoreFingerprintChainVerification verification = store.ReadAndVerify();

			Assert.True(Enum.IsDefined(verification.State), label);
			Assert.False(string.IsNullOrWhiteSpace(verification.Message), label);
			Assert.True(verification.State != StoreFingerprintChainState.Ok, label + " -> " + verification.Message);
		});

	/// <summary>Writes a fresh two-entry store in a temp root of its own and hands it to
	/// <paramref name="body"/> together with its chain folder. The private root is deliberate: mutations are not
	/// reversible, and a case that inherited a previous case's file would be testing several defects at once -
	/// this loop once removed every top-level property in turn and reduced the file to "{}", which then failed as
	/// a puzzle about a missing key instead of as the assertion that was wrong.</summary>
	private void WithFreshStore(Action<StoreFingerprintStore, string> body)
	{
		string root = Path.Combine(Path.GetTempPath(), "rdpaudit-fpmutation-" + Guid.NewGuid().ToString("N"));
		try
		{
			string integrity = Path.Combine(root, "integrity");
			string chainDirectory = Path.Combine(integrity, RdpAuditPaths.StoreFingerprintChainFolderName);
			StoreFingerprintStore store = new(
				Path.Combine(integrity, RdpAuditPaths.StoreFingerprintFileName),
				Path.Combine(integrity, RdpAuditPaths.StoreIntegrityAnomalyMarkerFileName),
				chainDirectory,
				Path.Combine(integrity, RdpAuditPaths.StoreFingerprintSealedTipFileName),
				_protector,
				_sink,
				NullLogger<StoreFingerprintStore>.Instance);
			store.Write(Fingerprint("Shutdown", clean: true, rows: 10), cleanShutdown: true);
			store.Write(Fingerprint("Schedule", clean: false, rows: 12), cleanShutdown: false);
			body(store, chainDirectory);
		}
		finally
		{
			try
			{
				if (Directory.Exists(root))
				{
					Directory.Delete(root, recursive: true);
				}
			}
			catch (IOException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
		}
	}

	/// <summary>Replaces a dotted property path with the given JSON value. The value is cloned per use: a JSON
	/// node can belong to one parent at a time, and the same mutation is applied to a fresh file many times.</summary>
	private static string WithJsonValue(string original, string propertyPath, JsonNode value)
	{
		JsonObject root = JsonNode.Parse(original)!.AsObject();
		SetJson(root, propertyPath, value.DeepClone());
		return root.ToJsonString();
	}

	/// <summary>Removes a dotted property path, which the entry type requires to be PRESENT.</summary>
	private static string RemoveJson(string original, string propertyPath)
	{
		JsonObject root = JsonNode.Parse(original)!.AsObject();
		string[] segments = propertyPath.Split('.');
		JsonObject target = root;
		for (int index = 0; index < segments.Length - 1; index++)
		{
			target = target[segments[index]]!.AsObject();
		}

		Assert.True(target.Remove(segments[^1]), "The entry file no longer carries " + propertyPath + ".");
		return root.ToJsonString();
	}

	/// <summary>Writes an EXPLICIT JSON <c>null</c> at a dotted property path.
	/// <para>
	/// The <c>JsonNode</c> API cannot express that: assigning <c>null</c> to a property REMOVES it, which is a
	/// different defect (a missing required field, a different finding) from the one B22 is about. So the
	/// document is rebuilt through a dictionary, where <c>null</c> is an ordinary value and serializes as
	/// <c>null</c>. Nested objects become dictionaries for the same reason; everything else keeps its parsed
	/// form.
	/// </para>
	/// </summary>
	private static string WithExplicitNull(string original, string propertyPath)
	{
		string[] segments = propertyPath.Split('.');
		Dictionary<string, object?> document = ToMutable(JsonNode.Parse(original)!.AsObject());
		Dictionary<string, object?> target = document;
		for (int index = 0; index < segments.Length - 1; index++)
		{
			Assert.True(target.ContainsKey(segments[index]), segments[index] + " is missing in " + propertyPath + ".");
			target = (Dictionary<string, object?>)target[segments[index]]!;
		}

		Assert.True(target.ContainsKey(segments[^1]), "The entry file no longer carries " + propertyPath + ".");
		target[segments[^1]] = null;
		return JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
	}

	private static Dictionary<string, object?> ToMutable(JsonObject source)
	{
		Dictionary<string, object?> result = [];
		foreach ((string key, JsonNode? value) in source)
		{
			// A nested object becomes a dictionary so a field inside it can be set to null; everything else -
			// strings, numbers, booleans, arrays - is carried over through its parsed form, which serializes
			// back exactly as it was written.
			result[key] = value is JsonObject nested
				? ToMutable(nested)
				: value is null ? null : JsonSerializer.Deserialize<object>(value.ToJsonString());
		}

		return result;
	}

	/// <summary>Compares two files by their parsed content, so a formatting difference is not confused with a
	/// mutation.</summary>
	private static string Normalize(string json) => JsonNode.Parse(json)!.ToJsonString();

	/// <summary>Sets a dotted property path ("Fingerprint.TableRowCounts") in a parsed entry.</summary>
	private static void SetJson(JsonObject root, string propertyPath, JsonNode? value)
	{
		string[] segments = propertyPath.Split('.');
		JsonObject target = root;
		for (int index = 0; index < segments.Length - 1; index++)
		{
			target = target[segments[index]]!.AsObject();
		}

		target[segments[^1]] = value;
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	/// <summary>Makes the tip write fail at exactly the point a crash would land - after the chain entry is
	/// durable, before the tip is replaced - by putting a DIRECTORY where the tip's temp file belongs. The write
	/// of the temp file is the first thing the tip write does, so the failure lands before anything touches the
	/// sealed tip: the OLD tip stays on disk and the chain is one entry longer, which is the interrupted shape.
	/// Nothing production-side knows about this, and the state it produces is the state a killed process
	/// leaves.</summary>
	private void InterruptTheTipWrite() => Directory.CreateDirectory(_tipPath + ".tmp");

	private void RestoreTheTipPath()
	{
		if (Directory.Exists(_tipPath + ".tmp"))
		{
			Directory.Delete(_tipPath + ".tmp");
		}
	}

	/// <summary>The base64 payload of a protected envelope: the only part of the tip file whose content is the
	/// tip. Editing the file through this helper keeps it a well-formed envelope and changes the bytes an
	/// unseal actually reads, which is what a tamper of the second store is.</summary>
	private static string ExtractPayload(string envelopeText)
	{
		using JsonDocument document = JsonDocument.Parse(envelopeText);
		return document.RootElement.GetProperty("$protected").GetString()!;
	}

	/// <summary>Rewrites the payload editing only the bits the LAST base64 character does not contribute to any
	/// decoded byte: with one or two bytes left over in the final group, its low bit is discarded, so the cipher
	/// bytes - and therefore the record every protector unseals - are unchanged.</summary>
	private static string FlipUnusedBase64Bits(string envelopeText)
	{
		string payload = ExtractPayload(envelopeText);
		int paddingIndex = payload.IndexOf('=', StringComparison.Ordinal);
		int lastPayloadIndex = paddingIndex < 0 ? payload.Length - 1 : paddingIndex - 1;
		char[] characters = payload.ToCharArray();
		characters[lastPayloadIndex] = s_base64Alphabet[s_base64Alphabet.IndexOf(characters[lastPayloadIndex], StringComparison.Ordinal) ^ 1];
		return envelopeText.Replace(payload, new string(characters), StringComparison.Ordinal);
	}

	private const string s_base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	private StoreFingerprintStore CreateStore() => new(
		_fingerprintPath,
		_anomalyMarkerPath,
		_chainDirectory,
		_tipPath,
		_protector,
		_sink,
		NullLogger<StoreFingerprintStore>.Instance);

	private static StoreFingerprint Fingerprint(string capturedBy, bool clean, long rows) => new()
	{
		CapturedUtc = DateTime.UtcNow,
		CleanShutdown = clean,
		CapturedBy = capturedBy,
		DatabaseBytes = 4096 + rows,
		WalBytes = 64,
		DatabaseLastWriteUtc = DateTime.UtcNow,
		LastIngestionSequence = rows,
		TableRowCounts = new Dictionary<string, long>(StringComparer.Ordinal) { ["RawEvents"] = rows },
		AppliedMigrations = ["20260504215120_InitialCreate"],
		LedgerChainedRows = 0,
		LedgerUnchainedRows = 0,
		LedgerChainIntact = true,
	};

	/// <summary>Records what the store asked to mirror, so the tests can assert the key facts actually leave
	/// the integrity folder rather than assuming it.</summary>
	private sealed class FakeStoreFingerprintAlarmSink : IStoreFingerprintAlarmSink
	{
		public List<StoreFingerprintAlarm> Published { get; } = [];

		public bool IsAvailable => true;

		public string UnavailableReason => string.Empty;

		public void Publish(StoreFingerprintAlarm alarm) => Published.Add(alarm);
	}
}
