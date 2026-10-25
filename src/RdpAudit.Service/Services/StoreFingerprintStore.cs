// File:    src/RdpAudit.Service/Services/StoreFingerprintStore.cs
// Module:  RdpAudit.Service.Services
// Purpose: Durable, crash-tolerant persistence of the store fingerprints and the anomaly marker.
//          LAYOUT (B19): the fingerprints are a CHAIN, not a rewritten document.
//            integrity\fingerprints\fingerprint-0000000001.json, ...0002.json, ...
//              one immutable entry per capture; each entry carries its own digest and the digest of its
//              predecessor, so an entry cannot be edited, reordered or removed from the middle without
//              breaking the linkage (ChainBroken).
//            integrity\store-fingerprint-sealed.json
//              the SEALED TIP - how many entries the chain should hold and what its head digest is - written
//              through ISecretProtector (DPAPI on Windows). A deleted chain TAIL cannot be revealed by a
//              prefix of a valid chain, which is exactly why the tip is a second store: when it accounts for
//              entries that are not on disk the state is Missing, not "no data".
//            integrity\store-fingerprint.json
//              the pre-B19 single document. Read ONCE to migrate an existing installation into the chain and
//              then left on disk untouched as history; never written again.
//          Writes go through a temp file plus an atomic move, so a crash mid-write cannot leave a half-written
//          entry that the next start would misread as tampering.
//          The chain deliberately does NOT live inside the database: a fingerprint stored in the file it
//          describes could be rewritten together with the tampering it exists to reveal.
//          HONEST LIMIT, stated here because it is the whole point of B19: a local administrator can delete the
//          chain, delete the tip, or - because DPAPI LocalMachine is by design usable by any process on this
//          machine - re-seal a forged tip. NOTHING here makes tampering impossible. What it makes impossible
//          is tampering being INVISIBLE while the process still reports "ok": four distinct states
//          (Ok / Missing / Unreadable / ChainBroken) surface through the start-up report, the anomaly marker,
//          the operation log and, when the service's own event-log source exists, a mirror record outside
//          %ProgramData% (IStoreFingerprintAlarmSink).
// Extends: System.Object

using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>The persisted pair of fingerprints. Kept as the READ shape after B19: callers that only need the
/// two baselines (the comparer, the overview) keep working unchanged, while the chain state is available
/// through <see cref="StoreFingerprintStore.ReadAndVerify"/>.</summary>
public sealed class StoreFingerprintDocument
{
	/// <summary>Fingerprint taken at the last clean shutdown, or null when the service has never stopped
	/// cleanly since the feature was enabled.</summary>
	public StoreFingerprint? LastCleanShutdown { get; set; }

	/// <summary>Fingerprint taken by the most recent periodic capture, or null.</summary>
	public StoreFingerprint? LastPeriodic { get; set; }
}

/// <summary>Reads and writes the durable store-fingerprint chain, its sealed tip and the anomaly marker.</summary>
public sealed class StoreFingerprintStore
{
	private static readonly JsonSerializerOptions SerializerOptions = new()
	{
		WriteIndented = true,
	};

	private readonly string _fingerprintPath;
	private readonly string _anomalyMarkerPath;
	private readonly string _chainDirectory;
	private readonly string _sealedTipPath;
	private readonly string _writeIntentPath;
	private readonly ISecretProtector? _protector;
	private readonly IStoreFingerprintAlarmSink _alarmSink;
	private readonly ILogger<StoreFingerprintStore> _logger;

	/// <summary>Creates the store for an explicit pair of paths (tests, custom layouts). The chain folder and
	/// the sealed tip are derived from the fingerprint file's directory, and the tip is written as plain JSON
	/// because no protector was supplied - which the verification reports through
	/// <see cref="StoreFingerprintStore.TipIsProtected"/> rather than hiding.</summary>
	public StoreFingerprintStore(
		string fingerprintPath,
		string anomalyMarkerPath,
		ILogger<StoreFingerprintStore> logger)
		: this(
			fingerprintPath,
			anomalyMarkerPath,
			DeriveChainDirectory(fingerprintPath),
			DeriveSealedTipPath(fingerprintPath),
			protector: null,
			alarmSink: null,
			logger)
	{
	}

	/// <summary>Creates the store at the machine's standard ProgramData locations, without a protector or a
	/// mirror sink. Prefer the overload that takes both: on Windows the tip must be DPAPI-protected.</summary>
	public StoreFingerprintStore(IRdpAuditPathsProvider paths, ILogger<StoreFingerprintStore> logger)
		: this(
			(paths ?? throw new ArgumentNullException(nameof(paths))).Paths.StoreFingerprintPath,
			paths.Paths.StoreIntegrityAnomalyMarkerPath,
			paths.Paths.StoreFingerprintChainDirectory,
			paths.Paths.StoreFingerprintSealedTipPath,
			protector: null,
			alarmSink: null,
			logger)
	{
	}

	/// <summary>Creates the store at the machine's standard ProgramData locations with the secret protector
	/// that seals the tip and the sink that mirrors the key facts outside the integrity folder.</summary>
	public StoreFingerprintStore(
		IRdpAuditPathsProvider paths,
		ISecretProtector? protector,
		IStoreFingerprintAlarmSink? alarmSink,
		ILogger<StoreFingerprintStore> logger)
		: this(
			(paths ?? throw new ArgumentNullException(nameof(paths))).Paths.StoreFingerprintPath,
			paths.Paths.StoreIntegrityAnomalyMarkerPath,
			paths.Paths.StoreFingerprintChainDirectory,
			paths.Paths.StoreFingerprintSealedTipPath,
			protector,
			alarmSink,
			logger)
	{
	}

	/// <summary>Creates the store over explicit paths.</summary>
	public StoreFingerprintStore(
		string fingerprintPath,
		string anomalyMarkerPath,
		string chainDirectory,
		string sealedTipPath,
		ISecretProtector? protector,
		IStoreFingerprintAlarmSink? alarmSink,
		ILogger<StoreFingerprintStore> logger)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(fingerprintPath);
		ArgumentException.ThrowIfNullOrWhiteSpace(anomalyMarkerPath);
		ArgumentException.ThrowIfNullOrWhiteSpace(chainDirectory);
		ArgumentException.ThrowIfNullOrWhiteSpace(sealedTipPath);
		ArgumentNullException.ThrowIfNull(logger);
		_fingerprintPath = fingerprintPath;
		_anomalyMarkerPath = anomalyMarkerPath;
		_chainDirectory = chainDirectory;
		_sealedTipPath = sealedTipPath;
		_writeIntentPath = DeriveWriteIntentPath(sealedTipPath);
		_protector = protector;
		_alarmSink = alarmSink ?? NullStoreFingerprintAlarmSink.Instance;
		_logger = logger;
	}

	/// <summary>Absolute path of the pre-B19 fingerprint document (migration source, never written again).</summary>
	public string FingerprintPath => _fingerprintPath;

	/// <summary>Absolute path of the anomaly marker (diagnostics and tests).</summary>
	public string AnomalyMarkerPath => _anomalyMarkerPath;

	/// <summary>Absolute path of the fingerprint chain folder.</summary>
	public string ChainDirectory => _chainDirectory;

	/// <summary>Absolute path of the sealed fingerprint-chain tip.</summary>
	public string SealedTipPath => _sealedTipPath;

	/// <summary>Absolute path of the durable write intent (B24). It exists only while a capture is between
	/// appending its chain entry and re-sealing the tip, so finding it after a restart is what an interrupted
	/// capture leaves behind - and reading it back is what lets the verifier call that state
	/// <see cref="StoreFingerprintChainState.Interrupted"/> instead of an accusation of tampering.</summary>
	public string WriteIntentPath => _writeIntentPath;

	/// <summary>True when the tip is written as a protected envelope rather than plain JSON.</summary>
	public bool TipIsProtected => _protector is not null;

	/// <summary>True when the sink that mirrors the chain facts outside the integrity folder can publish on
	/// this host. False is a limitation to report, not a failure: see
	/// <see cref="IStoreFingerprintAlarmSink.UnavailableReason"/>.</summary>
	public bool AlarmMirrorAvailable => _alarmSink.IsAvailable;

	/// <summary>Why the mirror is unavailable; empty when it works.</summary>
	public string AlarmMirrorUnavailableReason => _alarmSink.UnavailableReason;

	// ── Reading ──────────────────────────────────────────────────────────────────

	/// <summary>Reads the two baselines the comparer needs, from the verified chain. The chain state itself is
	/// available from <see cref="ReadAndVerify"/>; this overload exists so the comparison path and older
	/// callers do not have to know about the chain.</summary>
	public StoreFingerprintDocument Read()
	{
		StoreFingerprintChainVerification verification = ReadAndVerify();
		return new StoreFingerprintDocument
		{
			LastCleanShutdown = verification.LastCleanShutdown?.Fingerprint,
			LastPeriodic = verification.LastPeriodic?.Fingerprint,
		};
	}

	/// <summary>Reads the chain, verifies it against its sealed tip, and reports one of the five states
	/// (Ok / Missing / Unreadable / ChainBroken / Interrupted) with the findings behind it. Never throws: a
	/// chain that cannot be read is reported as <see cref="StoreFingerprintChainState.Unreadable"/>, which is a
	/// loud state, never as "no data". Reading changes nothing on disk - the interrupted state is repaired by
	/// the next <see cref="Write"/>, not by the verifier, so a read-only observer (the Configurator's overview,
	/// a diagnostics pass) cannot alter the store it is inspecting.</summary>
	public StoreFingerprintChainVerification ReadAndVerify()
	{
		(List<StoreFingerprintChainEntry> entries, List<string> unreadable) = ReadChainEntries();
		(StoreFingerprintSealedTip? tip, bool tipReadable, string? tipFinding) = ReadSealedTip();
		if (tipFinding is not null)
		{
			unreadable.Add(tipFinding);
		}

		// The write intent is read last and cannot ADD a finding: it is the only input here that can make a
		// verdict *less* accusing, and it can do that only by agreeing, fact for fact, with a discrepancy the
		// chain and the tip already show. An intent that is missing, unreadable or of another version is
		// therefore indistinguishable from "no intent", and the strict verdict stands (B24).
		StoreFingerprintWriteIntent? writeIntent = ReadWriteIntent();

		StoreFingerprintChainVerification verification =
			StoreFingerprintChain.Verify(entries, tip, tipReadable, unreadable, writeIntent);

		if (verification.IsAlarming)
		{
			_logger.LogWarning(
				"The store-fingerprint chain reports {State}: {Message}",
				verification.State,
				verification.Message);
			_alarmSink.Publish(new StoreFingerprintAlarm(
				Kind: "ChainState",
				State: verification.State.ToString(),
				EntryCount: verification.EntryCount,
				HeadDigest: verification.Tip?.Digest ?? StoreFingerprintChain.GenesisDigest,
				Detail: verification.Message));
		}

		return verification;
	}

	// ── Writing ──────────────────────────────────────────────────────────────────

	/// <summary>Appends one chain entry for <paramref name="fingerprint"/> and re-seals the tip, through a temp
	/// file plus an atomic move.
	/// <para>
	/// B24 - the two steps are bracketed by a durable write INTENT, and the order is the point:
	/// </para>
	/// <list type="number">
	/// <item><description>the intent is written first, naming the entry that is about to be appended (count,
	/// sequence and digest);</description></item>
	/// <item><description>the entry is written and moved into place;</description></item>
	/// <item><description>the tip is re-sealed over the whole chain;</description></item>
	/// <item><description>only then is the intent removed.</description></item>
	/// </list>
	/// <para>
	/// A crash anywhere in the middle therefore always leaves the intent on disk next to the discrepancy it
	/// explains, and the next read reports <see cref="StoreFingerprintChainState.Interrupted"/> instead of
	/// accusing the store of being rolled back. A failure after the tip was written but before the intent was
	/// removed leaves an intent that explains nothing, which the verifier ignores. Any successful write
	/// re-seals the tip over every entry on disk, so a store left interrupted repairs itself on the next
	/// capture - including a process that failed here and had its exception swallowed below.
	/// </para>
	/// </summary>
	public void Write(StoreFingerprint fingerprint, bool cleanShutdown)
	{
		ArgumentNullException.ThrowIfNull(fingerprint);

		try
		{
			Directory.CreateDirectory(_chainDirectory);
			List<StoreFingerprintChainEntry> entries = LoadEntriesForAppend();

			// Complete the PREVIOUS capture first if it was interrupted. This is what keeps the recoverable state
			// narrow enough to stay safe: at most one entry is ever unsealed, so "the tip stops exactly one entry
			// short" remains the only shape an intent can explain. It is also what makes a PERSISTENT failure
			// honest - if the tip cannot be written, this throws before anything new is appended, so the store
			// stays at one unsealed append instead of drifting into a chain the tip describes less and less
			// (which the verifier would eventually have to call ChainBroken, a false tamper alarm for a full disk).
			CompleteAnInterruptedSeal(entries);

			StoreFingerprintChainEntry entry = new()
			{
				Sequence = entries.Count + 1,
				CapturedUtc = DateTime.UtcNow,
				CleanShutdown = cleanShutdown,
				CapturedBy = fingerprint.CapturedBy,
				PreviousDigest = entries.Count > 0 ? entries[^1].Digest : StoreFingerprintChain.GenesisDigest,
				Fingerprint = fingerprint,
			};
			entry = entry with { Digest = StoreFingerprintChain.ComputeDigest(entry) };

			// Before the entry exists: whatever happens from here on, the marker on disk describes the append
			// this call is performing. The entry's own sequence IS its position in the chain, because a chain
			// without a gap numbers its entries 1..N and a gap is reported as broken.
			StoreFingerprintWriteIntent intent = new()
			{
				ExpectedEntryCount = entry.Sequence,
				ExpectedHeadSequence = entry.Sequence,
				ExpectedHeadDigest = entry.Digest,
				StartedUtc = DateTime.UtcNow,
			};
			WriteAtomic(_writeIntentPath, SealIntent(intent));

			WriteAtomic(EntryPath(entry.Sequence), JsonSerializer.Serialize(entry, SerializerOptions));
			entries.Add(entry);
			StoreFingerprintSealedTip tip = StoreFingerprintChain.Seal(entries);
			WriteAtomic(_sealedTipPath, SealTip(tip));

			// The tip now accounts for the new entry, so the marker has nothing left to explain. Removing it
			// after the seal - never before - is what keeps the two states apart: an intent without a
			// discrepancy is ignored, a discrepancy without an intent is ChainBroken.
			ClearWriteIntent();

			if (cleanShutdown)
			{
				// The store was verified against a clean baseline: any earlier anomaly marker describes a
				// state that has since been superseded, so it is cleared rather than left to alarm a reader.
				ClearAnomalyMarker();

				// The authoritative tip is mirrored outside the integrity folder. Bounded by service
				// restarts, unlike the periodic captures, which the sealed tip alone covers.
				_alarmSink.Publish(new StoreFingerprintAlarm(
					Kind: "CleanShutdownTip",
					State: "Ok",
					EntryCount: tip.EntryCount,
					HeadDigest: tip.HeadDigest,
					Detail: string.Format(
						CultureInfo.InvariantCulture,
							"A clean-shutdown fingerprint was appended as chain entry {0}; the sealed tip now "
								+ "records {1} entr(ies) with head {2}.",
							entry.Sequence,
						tip.EntryCount,
						tip.HeadDigest)));
			}
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException
			or NotSupportedException or SecretProtectionException)
		{
			// Best effort but logged: losing a fingerprint costs a future comparison, never correctness. The
			// write intent, if this failure left one behind, is deliberately NOT removed here: it is the record
			// of what the interrupted write was doing, and the next read reports the store as interrupted
			// rather than as tampered with.
			_logger.LogWarning(ex, "The store fingerprint could not be written to {Path}", _chainDirectory);
		}
	}

	/// <summary>Writes the anomaly marker for an operator (and for the Configurator's diagnostics) to find
	/// without reading the service log. Best effort; the OperationLog row is the authoritative record.</summary>
	public void WriteAnomalyMarker(StoreIntegrityReport report)
	{
		ArgumentNullException.ThrowIfNull(report);

		try
		{
			string? directory = Path.GetDirectoryName(_anomalyMarkerPath);
			if (!string.IsNullOrEmpty(directory))
			{
				Directory.CreateDirectory(directory);
			}

			object marker = new
			{
				detectedUtc = DateTime.UtcNow,
				compared = report.Compared,
				baselineWasCleanShutdown = report.BaselineWasCleanShutdown,
				baselineCapturedUtc = report.BaselineCapturedUtc,
				ledgerChainIntact = report.LedgerChainIntact,
				message = report.Message,
				anomalies = report.Anomalies.Select(anomaly => new
				{
					severity = anomaly.Severity.ToString(),
					kind = anomaly.Kind,
					detail = anomaly.Detail,
				}),
			};
			File.WriteAllText(_anomalyMarkerPath, JsonSerializer.Serialize(marker, SerializerOptions));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			_logger.LogWarning(ex, "The store-integrity anomaly marker could not be written to {Path}", _anomalyMarkerPath);
		}
	}

	/// <summary>Removes the anomaly marker, if present.</summary>
	public void ClearAnomalyMarker()
	{
		try
		{
			if (File.Exists(_anomalyMarkerPath))
			{
				File.Delete(_anomalyMarkerPath);
			}
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			_logger.LogDebug(ex, "The store-integrity anomaly marker could not be removed");
		}
	}

	// ── Chain internals ──────────────────────────────────────────────────────────

	/// <summary>Loads the chain for the next append, migrating a pre-B19 document on the way: the legacy
	/// clean-shutdown slot becomes the chain's first entry and the legacy periodic slot the second, so an
	/// existing installation keeps its baseline instead of starting over. The legacy file is left in place.</summary>
	private List<StoreFingerprintChainEntry> LoadEntriesForAppend()
	{
		(List<StoreFingerprintChainEntry> entries, List<string> unreadable) = ReadChainEntries();

		if (entries.Count > 0 || unreadable.Count > 0)
		{
			return entries;
		}

		foreach (StoreFingerprint legacy in ReadLegacyFingerprints())
		{
			StoreFingerprintChainEntry entry = new()
			{
				Sequence = entries.Count + 1,
				CapturedUtc = legacy.CapturedUtc,
				CleanShutdown = legacy.CleanShutdown,
				CapturedBy = legacy.CapturedBy,
				PreviousDigest = entries.Count > 0 ? entries[^1].Digest : StoreFingerprintChain.GenesisDigest,
				Fingerprint = legacy,
			};
			entry = entry with { Digest = StoreFingerprintChain.ComputeDigest(entry) };
			WriteAtomic(EntryPath(entry.Sequence), JsonSerializer.Serialize(entry, SerializerOptions));
			entries.Add(entry);
		}

		if (entries.Count > 0)
		{
			_logger.LogInformation(
				"Migrated {Count} pre-B19 fingerprint slot(s) into the fingerprint chain at {Path}",
				entries.Count,
				_chainDirectory);
		}

		return entries;
	}

	/// <summary>The pre-B19 document's slots, in the order they were captured. An unreadable document is
	/// reported and yields nothing, and so is a slot that carries a <c>null</c> where this layout always writes a
	/// value: the migration must never fabricate a baseline, and it must not migrate a payload that the chain
	/// reader would then report as unreadable either - an entry written from it could never be verified, which
	/// would leave the chain permanently short of its tip (B22).</summary>
	private List<StoreFingerprint> ReadLegacyFingerprints()
	{
		try
		{
			if (!File.Exists(_fingerprintPath))
			{
				return [];
			}

			StoreFingerprintDocument? document = JsonSerializer.Deserialize<StoreFingerprintDocument>(
				File.ReadAllText(_fingerprintPath),
				SerializerOptions);
			List<StoreFingerprint> ordered = [];
			AddLegacySlot(document?.LastCleanShutdown);
			AddLegacySlot(document?.LastPeriodic);
			return ordered;

			void AddLegacySlot(StoreFingerprint? slot)
			{
				if (slot is null)
				{
					return;
				}

				string? nullField = StoreFingerprintChain.DescribeNullField(slot);
				if (nullField is not null)
				{
					_logger.LogWarning(
						"The pre-B19 store fingerprint at {Path} carries \"null\" in {Field}, a field every writer "
							+ "of this layout fills in: that slot is NOT migrated, because an entry written from it "
							+ "could not be read back.",
						_fingerprintPath,
						nullField);
					return;
				}

				ordered.Add(slot);
			}
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
		{
			_logger.LogWarning(ex, "The pre-B19 store fingerprint at {Path} could not be read for migration", _fingerprintPath);
			return [];
		}
	}

	private (List<StoreFingerprintChainEntry> Entries, List<string> Unreadable) ReadChainEntries()
	{
		List<StoreFingerprintChainEntry> entries = [];
		List<string> unreadable = [];

		if (!Directory.Exists(_chainDirectory))
		{
			return (entries, unreadable);
		}

		string[] files;
		try
		{
			files = Directory.GetFiles(
				_chainDirectory,
				RdpAuditPaths.StoreFingerprintChainEntryPrefix + "*.json",
				SearchOption.TopDirectoryOnly);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			unreadable.Add("The fingerprint chain folder " + _chainDirectory + " could not be listed: "
				+ ex.GetType().Name + " - " + ex.Message + ". The chain is UNVERIFIED.");
			return (entries, unreadable);
		}

		foreach (string file in files)
		{
			try
			{
				StoreFingerprintChainEntry? entry = JsonSerializer.Deserialize<StoreFingerprintChainEntry>(
					File.ReadAllText(file),
					SerializerOptions);
				if (entry is null)
				{
					unreadable.Add(Path.GetFileName(file) + " parsed as an empty fingerprint entry.");
					continue;
				}

				// B22 - a field this layout always writes but that carries no value. A missing property already
				// fails to deserialize (every field is required), and a property explicitly set to null is the
				// same situation one step further: there is nothing to read, so the entry is reported as one we
				// could not read rather than being fed to the digest as an invented empty value (which A10
				// removed) or crashing the read path on a dereference (which is what a null
				// "TableRowCounts" used to do). The field is named, so the finding is actionable.
				string? nullField = StoreFingerprintChain.DescribeNullField(entry);
				if (nullField is not null)
				{
					unreadable.Add(Path.GetFileName(file) + " carries \"null\" in " + nullField
						+ ", a field every writer of this layout fills in: the entry could not be read.");
					continue;
				}

				if (string.IsNullOrEmpty(entry.Digest))
				{
					unreadable.Add(Path.GetFileName(file) + " parsed as an empty fingerprint entry.");
					continue;
				}

				if (entry.FormatVersion != StoreFingerprintChainEntry.CurrentFormatVersion)
				{
					unreadable.Add(string.Format(
						CultureInfo.InvariantCulture,
						"{0} uses fingerprint-chain layout version {1} while this build reads {2}: it is NOT "
							+ "verified, so the chain's integrity is unknown rather than confirmed.",
						Path.GetFileName(file),
						entry.FormatVersion,
						StoreFingerprintChainEntry.CurrentFormatVersion));
					continue;
				}

				entries.Add(entry);
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
			{
				unreadable.Add(Path.GetFileName(file) + " could not be read: " + ex.GetType().Name + " - "
					+ ex.Message + ".");
			}
		}

		entries.Sort((left, right) => left.Sequence.CompareTo(right.Sequence));
		return (entries, unreadable);
	}

	private (StoreFingerprintSealedTip? Tip, bool Readable, string? Finding) ReadSealedTip()
	{
		if (!File.Exists(_sealedTipPath))
		{
			return (null, true, null);
		}

		string text;
		try
		{
			text = File.ReadAllText(_sealedTipPath);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			return (null, false, "The sealed fingerprint tip at " + _sealedTipPath + " could not be read: "
				+ ex.GetType().Name + " - " + ex.Message + ". The chain's length is UNVERIFIED, so a deleted "
				+ "entry cannot be ruled out.");
		}

		if (_protector is not null && !_protector.IsProtectedEnvelope(text))
		{
			return (null, false, "The sealed fingerprint tip exists but is NOT a protected envelope: it was "
				+ "replaced with plain text. The chain's length is UNVERIFIED, so a deleted entry cannot be "
				+ "ruled out.");
		}

		try
		{
			string json = _protector is null ? text : _protector.Unprotect(text);
			StoreFingerprintSealedTip? tip = JsonSerializer.Deserialize<StoreFingerprintSealedTip>(json, SerializerOptions);
			if (tip is null || !StoreFingerprintChain.IsDigestShaped(tip.HeadDigest))
			{
				return (null, false, "The sealed fingerprint tip did not contain a readable tip record: its "
					+ "integrity check failed or its content was truncated.");
			}

			// B23 - the tip's layout version is compared exactly the way a chain entry's is. A tip written by a
			// build whose fields mean something else would otherwise be read under this layout's rules, field by
			// field: the shape looks the same, the numbers and the digest do not mean the same thing, and the
			// verdict would be a confirmation nobody issued. Report it as unreadable instead - we could not read
			// this tip, so the chain's length is UNVERIFIED.
			if (tip.FormatVersion != StoreFingerprintSealedTip.CurrentFormatVersion)
			{
				return (null, false, string.Format(
					CultureInfo.InvariantCulture,
					"The sealed fingerprint tip uses layout version {0} while this build reads {1}: it is NOT "
						+ "verified, so the chain's length is UNVERIFIED rather than confirmed and a deleted "
						+ "entry cannot be ruled out.",
					tip.FormatVersion,
					StoreFingerprintSealedTip.CurrentFormatVersion));
			}

			return (tip, true, null);
		}
		catch (Exception ex) when (ex is JsonException or SecretProtectionException or CryptographicException
			or InvalidOperationException or FormatException)
		{
			// A DPAPI blob whose bytes were altered fails here: the envelope carries its own integrity check,
			// so this is the "someone edited the second store" case and it must be loud.
			return (null, false, "The sealed fingerprint tip could not be unsealed or parsed ("
				+ ex.GetType().Name + " - " + ex.Message + "): it was modified after it was written, or it was "
				+ "written by another machine/account.");
		}
	}

	private string SealTip(StoreFingerprintSealedTip tip)
	{
		string json = JsonSerializer.Serialize(tip, SerializerOptions);
		if (_protector is null || !_protector.IsAvailable)
		{
			return json;
		}

		// Protect throws SecretProtectionException on failure, and Write() treats that as a failed capture:
		// writing the tip in the clear would silently downgrade the second store, so the previous tip and the
		// previous chain state are kept instead and the operator sees the logged warning.
		return _protector.Protect(json);
	}

	/// <summary>Re-seals the tip over the chain as it stands when a previous capture was interrupted before it
	/// could, i.e. when the tip accounts for FEWER entries than are on disk. Nothing is done in the other
	/// direction: a tip that accounts for more entries than are on disk is a deleted tail, and re-sealing the tip
	/// over the shorter chain would ratify the deletion instead of leaving it visible to the verifier. A tip that
	/// could not be read at all is left alone for the same reason - an unreadable second store is an alarm, not
	/// something to overwrite with a fresh one.
	/// </summary>
	private void CompleteAnInterruptedSeal(List<StoreFingerprintChainEntry> entries)
	{
		(StoreFingerprintSealedTip? tip, bool tipReadable, _) = ReadSealedTip();
		if (!tipReadable || tip is null || tip.EntryCount >= entries.Count)
		{
			return;
		}

		WriteAtomic(_sealedTipPath, SealTip(StoreFingerprintChain.Seal(entries)));
		_logger.LogInformation(
			"A fingerprint capture that was interrupted before it could re-seal its tip ({SealedCount} of "
				+ "{EntryCount} entr(ies) were accounted for) has been completed: the tip now seals the chain on disk.",
			tip.EntryCount,
			entries.Count);
	}

	/// <summary>Seals the write intent with the same protector as the tip, for the same reason: the intent is
	/// evidence about a write, and evidence a plain-text file can be produced for by anyone who can write the
	/// folder is weaker than it needs to be. Without a protector (a test host, a non-Windows layout) it is
	/// plain JSON and the store reports that limitation through <see cref="TipIsProtected"/> on the tip
	/// itself.</summary>
	private string SealIntent(StoreFingerprintWriteIntent intent)
	{
		string json = JsonSerializer.Serialize(intent, SerializerOptions);
		if (_protector is null || !_protector.IsAvailable)
		{
			return json;
		}

		return _protector.Protect(json);
	}

	/// <summary>Reads the durable write intent, or null when there is none to use.
	/// <para>
	/// Every outcome other than "a well-formed intent of this layout" returns null, and null means "no
	/// intent": a missing file, an unreadable one, one that is not a protected envelope when a protector is
	/// configured, one that does not parse, one from another layout version. That is deliberate and
	/// fail-closed - the intent can only ever soften one verdict, so being unable to read it must cost the
	/// softening and never the detection. It is also why a damaged intent is not itself an alarm: it is not
	/// part of the chain, and the discrepancy it would have explained is still reported by the strict path.
	/// </para>
	/// </summary>
	private StoreFingerprintWriteIntent? ReadWriteIntent()
	{
		string text;
		try
		{
			if (!File.Exists(_writeIntentPath))
			{
				return null;
			}

			text = File.ReadAllText(_writeIntentPath);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			_logger.LogWarning(ex, "The store-fingerprint write intent at {Path} could not be read", _writeIntentPath);
			return null;
		}

		if (_protector is not null && !_protector.IsProtectedEnvelope(text))
		{
			// A plain-text intent where this host seals them is not something this build wrote.
			return null;
		}

		try
		{
			string json = _protector is null ? text : _protector.Unprotect(text);
			StoreFingerprintWriteIntent? intent =
				JsonSerializer.Deserialize<StoreFingerprintWriteIntent>(json, SerializerOptions);
			if (intent is null || intent.FormatVersion != StoreFingerprintWriteIntent.CurrentFormatVersion)
			{
				return null;
			}

			return intent;
		}
		catch (Exception ex) when (ex is JsonException or SecretProtectionException or CryptographicException
			or InvalidOperationException or FormatException)
		{
			_logger.LogWarning(ex, "The store-fingerprint write intent at {Path} could not be used", _writeIntentPath);
			return null;
		}
	}

	/// <summary>Removes the write intent, if present. Best effort: a leftover intent is harmless once the tip
	/// accounts for the whole chain (it explains nothing and is ignored), so a failure to delete it must not
	/// fail the capture that just succeeded.</summary>
	private void ClearWriteIntent()
	{
		try
		{
			if (File.Exists(_writeIntentPath))
			{
				File.Delete(_writeIntentPath);
			}
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			_logger.LogDebug(ex, "The store-fingerprint write intent could not be removed");
		}
	}

	private string EntryPath(int sequence)
		=> Path.Combine(
			_chainDirectory,
			RdpAuditPaths.StoreFingerprintChainEntryPrefix
				+ sequence.ToString("D10", CultureInfo.InvariantCulture)
				+ ".json");

	private static void WriteAtomic(string path, string content)
	{
		string? directory = Path.GetDirectoryName(path);
		if (!string.IsNullOrEmpty(directory))
		{
			Directory.CreateDirectory(directory);
		}

		string tempPath = path + ".tmp";
		File.WriteAllText(tempPath, content);
		File.Move(tempPath, path, overwrite: true);
	}

	private static string DeriveChainDirectory(string fingerprintPath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(fingerprintPath);
		string? directory = Path.GetDirectoryName(Path.GetFullPath(fingerprintPath));
		return Path.Combine(
			string.IsNullOrEmpty(directory) ? "." : directory,
			RdpAuditPaths.StoreFingerprintChainFolderName);
	}

	private static string DeriveSealedTipPath(string fingerprintPath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(fingerprintPath);
		string? directory = Path.GetDirectoryName(Path.GetFullPath(fingerprintPath));
		return Path.Combine(
			string.IsNullOrEmpty(directory) ? "." : directory,
			RdpAuditPaths.StoreFingerprintSealedTipFileName);
	}

	/// <summary>The write intent sits next to the sealed tip: same directory, same protected-or-plain form, same
	/// lifetime as a two-phase write. Derived from the tip's path rather than taken as another constructor
	/// argument, so every existing caller - and every deployment - gets the new marker in the right folder
	/// without changing how the store is constructed.</summary>
	private static string DeriveWriteIntentPath(string sealedTipPath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(sealedTipPath);
		string? directory = Path.GetDirectoryName(Path.GetFullPath(sealedTipPath));
		return Path.Combine(
			string.IsNullOrEmpty(directory) ? "." : directory,
			RdpAuditPaths.StoreFingerprintWriteIntentFileName);
	}
}
