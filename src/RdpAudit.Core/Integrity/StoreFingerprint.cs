/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StoreFingerprint.cs
// Project: RdpAudit.Core (RdpAudit.Core.Integrity)
// Purpose: The durable fingerprint of the evidence store and the rules that decide what counts as an anomaly
//          when the store is inspected again. It answers one question: "was the store changed while this
//          service was not running?"
//          The rules are stated here, in one place, with the false-positive each of them could produce and
//          the reason it does not:
//            - Row counts may legitimately fall while the service RUNS (retention, pressure passes, purges,
//              shard eviction). They may not fall while it is STOPPED. So a decrease is only an anomaly when
//              the baseline fingerprint was taken at a clean shutdown; against a periodic baseline it is
//              withheld, because a crash after a retention pass would otherwise look like tampering on every
//              restart - the false alarm that makes operators stop reading the alarm.
//            - The migration history may legitimately GROW between two runs (binaries were upgraded). It may
//              not lose, reorder or replace entries. So the anomaly is "the previous list is not a prefix of
//              the current one", which accepts an upgrade and rejects a swap or a rollback.
//            - The ingestion sequence may legitimately grow while the service runs. Recorded by a clean
//              shutdown it is final, so a higher value at the next start means rows were written while the
//              service was down - a real anomaly.
//            - A decrease in the database FILE size is reported as information, not as tampering: an offline
//              compaction or a restore both shrink it legitimately.
//            - A shorter ledger, a broken ledger chain, or a database file modified after the baseline was
//              taken are reported as tampering. A restore from a snapshot triggers exactly these, which is
//              correct: the store genuinely changed while the service was down, and the operator performed
//              that change deliberately. The report says so instead of suppressing it.
// Depends: LedgerChainHasher
// Extends: Add a field to StoreFingerprint together with its rule in StoreIntegrityComparer and its
//          justification comment; a field nobody compares is a field that silently does nothing.

namespace RdpAudit.Core.Integrity;

/// <summary>Severity of an observed store-integrity anomaly.</summary>
public enum StoreIntegritySeverity
{
	/// <summary>Worth recording, not evidence of interference (for example the file shrank).</summary>
	Information = 0,

	/// <summary>The store changed in a way that is explainable, but only by an operator action such as a
	/// restore. Report it so the change is acknowledged rather than assumed.</summary>
	Warning = 1,

	/// <summary>The store changed in a way that no supported operation explains: rows vanished while the
	/// service was down, the ledger lost entries or its chain broke.</summary>
	Strong = 2,
}

/// <summary>One observed difference between two fingerprints.</summary>
public sealed record StoreIntegrityAnomaly(StoreIntegritySeverity Severity, string Kind, string Detail);

/// <summary>Durable snapshot of the evidence store's shape at one moment.</summary>
public sealed record StoreFingerprint
{
	/// <summary>Fingerprint layout version. Raised when the meaning of a field changes, so a comparison
	/// against an older file is skipped instead of misread.</summary>
	public const int CurrentFormatVersion = 1;

	/// <summary>Layout version of this record.</summary>
	public int FormatVersion { get; init; } = CurrentFormatVersion;

	/// <summary>When the fingerprint was taken (UTC).</summary>
	public DateTime CapturedUtc { get; init; }

	/// <summary>True when it was taken as the service shut down, which makes it the authoritative baseline:
	/// only such a fingerprint proves that no writer remained.</summary>
	public bool CleanShutdown { get; init; }

	/// <summary>What took it: <c>Shutdown</c> or <c>Schedule</c>.</summary>
	public string CapturedBy { get; init; } = string.Empty;

	/// <summary>Main database file length in bytes, or -1 when it could not be read.</summary>
	public long DatabaseBytes { get; init; } = -1;

	/// <summary>WAL sidecar length in bytes, or -1 when it does not exist.</summary>
	public long WalBytes { get; init; } = -1;

	/// <summary>Last write time of the database file in UTC, or null when unavailable.</summary>
	public DateTime? DatabaseLastWriteUtc { get; init; }

	/// <summary>Highest durable ingestion sequence present in the store, or 0 when the table is empty.</summary>
	public long LastIngestionSequence { get; init; }

	/// <summary>Row count of every table the store watches. A dictionary rather than a fixed shape so a new
	/// table is covered the moment it is added to the counted set, without a format change.</summary>
	public Dictionary<string, long> TableRowCounts { get; init; } = new(StringComparer.Ordinal);

	/// <summary>Applied EF migrations, in application order.</summary>
	public List<string> AppliedMigrations { get; init; } = [];

	/// <summary>Number of ledger rows that carry a hash link.</summary>
	public long LedgerChainedRows { get; init; }

	/// <summary>Number of ledger rows written before the chain existed.</summary>
	public long LedgerUnchainedRows { get; init; }

	/// <summary>EntryHash of the newest chained ledger row, or the genesis value.</summary>
	public string LedgerChainHead { get; init; } = LedgerChainHasher.GenesisPreviousHash;

	/// <summary>Whether the ledger chain verified when this fingerprint was taken.</summary>
	public bool LedgerChainIntact { get; init; } = true;
}

/// <summary>Result of comparing a stored fingerprint against the current state.</summary>
public sealed record StoreIntegrityReport(
	bool Compared,
	bool BaselineWasCleanShutdown,
	DateTime? BaselineCapturedUtc,
	IReadOnlyList<StoreIntegrityAnomaly> Anomalies,
	bool LedgerChainIntact,
	string Message)
{
	/// <summary>True when at least one anomaly of Warning or Strong severity was observed.</summary>
	public bool HasAnomalies => Anomalies.Any(anomaly => anomaly.Severity != StoreIntegritySeverity.Information);

	/// <summary>True when at least one anomaly of Strong severity was observed.</summary>
	public bool HasStrongAnomalies => Anomalies.Any(anomaly => anomaly.Severity == StoreIntegritySeverity.Strong);
}
