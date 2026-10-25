/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StoreIntegrityComparer.cs
// Project: RdpAudit.Core (RdpAudit.Core.Integrity)
// Purpose: The pure comparison behind the offline-change detector. Keeping it pure - two immutable records
//          in, a list of anomalies out - is what makes the false-positive question answerable by reading one
//          method instead of reasoning about a running service, and it lets the tests drive every case
//          (a legitimately shrunk table, a legitimately grown migration list, a forged ledger) without a
//          database.
//          The justification for each rule, including the false positive it avoids, is on the rule itself and
//          summarised in StoreFingerprint's header.
// Depends: StoreFingerprint
// Extends: Every new field on StoreFingerprint needs a rule here or it is dead weight; every new rule needs
//          a false-positive justification in its comment.

using System.Globalization;

namespace RdpAudit.Core.Integrity;

/// <summary>Compares two store fingerprints and states what, if anything, looks wrong.</summary>
public static class StoreIntegrityComparer
{
	/// <summary>Compares <paramref name="previous"/> against <paramref name="current"/>. A null or
	/// differently-versioned baseline yields a report with <see cref="StoreIntegrityReport.Compared"/> false:
	/// "nothing to compare against" is reported as exactly that, never as "clean".</summary>
	public static StoreIntegrityReport Compare(StoreFingerprint? previous, StoreFingerprint current)
	{
		ArgumentNullException.ThrowIfNull(current);

		if (previous is null)
		{
			return new StoreIntegrityReport(
				Compared: false,
				BaselineWasCleanShutdown: false,
				BaselineCapturedUtc: null,
				Anomalies: [],
				LedgerChainIntact: current.LedgerChainIntact,
				Message: "No stored fingerprint exists yet, so there is nothing to compare this start against. "
					+ "A fingerprint is written at every clean shutdown and periodically by the maintenance "
					+ "worker.");
		}

		if (previous.FormatVersion != StoreFingerprint.CurrentFormatVersion)
		{
			return new StoreIntegrityReport(
				Compared: false,
				BaselineWasCleanShutdown: previous.CleanShutdown,
				BaselineCapturedUtc: previous.CapturedUtc,
				Anomalies: [],
				LedgerChainIntact: current.LedgerChainIntact,
				Message: string.Format(
					CultureInfo.InvariantCulture,
					"The stored fingerprint uses format version {0} while this build writes {1}, so it is not "
						+ "compared. The next clean shutdown replaces it.",
					previous.FormatVersion,
					StoreFingerprint.CurrentFormatVersion));
		}

		List<StoreIntegrityAnomaly> anomalies = [];
		bool authoritative = previous.CleanShutdown;

		// ── Rule 1: the ledger's own hash chain ──────────────────────────────────
		// Always evaluated, regardless of the baseline: a broken chain is a statement about the store's
		// content, not about when it was written, and the chain is the one structure that is designed to
		// notice editing after the fact.
		if (!current.LedgerChainIntact)
		{
			anomalies.Add(new StoreIntegrityAnomaly(
				StoreIntegritySeverity.Strong,
				"LedgerChainBroken",
				"The deletion-ledger hash chain does not verify: a ledger entry was modified, removed from the "
					+ "middle, or reordered after it was written. Deletions recorded after the break cannot be "
					+ "trusted."));
		}
		else if (current.LedgerChainedRows < previous.LedgerChainedRows)
		{
			anomalies.Add(new StoreIntegrityAnomaly(
				StoreIntegritySeverity.Strong,
				"LedgerShrank",
				string.Format(
					CultureInfo.InvariantCulture,
					"The ledger holds {0} chained entry(ies) against {1} at the baseline. The ledger is "
						+ "append-only, so entries are missing. (Restoring an older snapshot produces this "
						+ "observation too.)",
					current.LedgerChainedRows,
					previous.LedgerChainedRows)));
		}

		// ── Rule 2: the migration history ────────────────────────────────────────
		// An upgrade appends migrations; nothing supported removes, reorders or replaces them. Requiring the
		// previous list to be a PREFIX of the current one therefore accepts every legitimate upgrade and
		// rejects a rollback or a substituted history.
		if (!IsPrefix(previous.AppliedMigrations, current.AppliedMigrations))
		{
			anomalies.Add(new StoreIntegrityAnomaly(
				StoreIntegritySeverity.Strong,
				"MigrationHistoryChanged",
				string.Format(
					CultureInfo.InvariantCulture,
					"The applied-migration history is not an extension of the baseline: {0} entr(ies) then, {1} "
						+ "now, and the baseline list is not a prefix of it. Migrations are only ever appended, "
						+ "so the history was rolled back, reordered or replaced.",
					previous.AppliedMigrations.Count,
					current.AppliedMigrations.Count)));
		}

		// ── Rule 3: writes that happened while the service was down ──────────────
		// Withheld unless the baseline came from a clean shutdown: a crash after a retention pass legitimately
		// leaves fewer rows and a larger sequence than the last periodic fingerprint recorded, and reporting
		// that as tampering on every restart is how an alarm stops being read.
		if (authoritative)
		{
			if (current.LastIngestionSequence > previous.LastIngestionSequence)
			{
				anomalies.Add(new StoreIntegrityAnomaly(
					StoreIntegritySeverity.Strong,
					"IngestionSequenceAdvanced",
					string.Format(
						CultureInfo.InvariantCulture,
						"The highest ingestion sequence advanced from {0} to {1} while the service was stopped, "
							+ "so rows were written to the store offline.",
						previous.LastIngestionSequence,
						current.LastIngestionSequence)));
			}

			if (previous.DatabaseLastWriteUtc is { } baselineWrite
				&& current.DatabaseLastWriteUtc is { } currentWrite
				&& currentWrite > baselineWrite.AddSeconds(2))
			{
				anomalies.Add(new StoreIntegrityAnomaly(
					StoreIntegritySeverity.Strong,
					"DatabaseModifiedOffline",
					string.Format(
						CultureInfo.InvariantCulture,
						"The database file was modified at {0:O} (UTC), after the baseline fingerprint was taken "
							+ "at {1:O} (UTC), which no supported offline operation performs on its own. A "
							+ "restore or an offline compaction also produces this observation - if you ran one, "
							+ "this is expected.",
						currentWrite,
						baselineWrite)));
			}

			foreach ((string table, long baselineCount) in previous.TableRowCounts.OrderBy(pair => pair.Key, StringComparer.Ordinal))
			{
				if (!current.TableRowCounts.TryGetValue(table, out long currentCount))
				{
					anomalies.Add(new StoreIntegrityAnomaly(
						StoreIntegritySeverity.Strong,
						"TableVanished",
						"The table " + table + " was present at the baseline and no longer exists."));
					continue;
				}

				if (currentCount < baselineCount)
				{
					anomalies.Add(new StoreIntegrityAnomaly(
						StoreIntegritySeverity.Strong,
						"RowsRemovedWhileStopped",
						string.Format(
							CultureInfo.InvariantCulture,
							"{0} holds {1} row(s) against {2} at the clean-shutdown baseline: {3} row(s) "
								+ "disappeared while the service was not running. Nothing in the product removes "
								+ "evidence while it is stopped. A restore of an older snapshot produces this "
								+ "observation too.",
							table,
							currentCount,
							baselineCount,
							baselineCount - currentCount)));
				}
			}
		}

		// ── Rule 4: informational observations ───────────────────────────────────
		// A smaller file is what an offline compaction is FOR, so it is recorded without an alarm.
		if (previous.DatabaseBytes > 0 && current.DatabaseBytes > 0 && current.DatabaseBytes < previous.DatabaseBytes)
		{
			anomalies.Add(new StoreIntegrityAnomaly(
				StoreIntegritySeverity.Information,
				"DatabaseShrank",
				string.Format(
					CultureInfo.InvariantCulture,
					"The database file is {0} bytes against {1} at the baseline; an offline compaction or a "
						+ "restore explains this.",
					current.DatabaseBytes,
					previous.DatabaseBytes)));
		}

		string message = anomalies.Count == 0
			? string.Format(
				CultureInfo.InvariantCulture,
				"No store-integrity anomaly: the state matches the {0} baseline taken at {1:O} (UTC).",
				previous.CleanShutdown ? "clean-shutdown" : "periodic",
				previous.CapturedUtc)
			: string.Format(
				CultureInfo.InvariantCulture,
				"{0} store-integrity observation(s) against the {1} baseline taken at {2:O} (UTC): {3}",
				anomalies.Count,
				previous.CleanShutdown ? "clean-shutdown" : "periodic",
				previous.CapturedUtc,
				string.Join(", ", anomalies.Select(anomaly => anomaly.Kind)));

		return new StoreIntegrityReport(
			Compared: true,
			BaselineWasCleanShutdown: previous.CleanShutdown,
			BaselineCapturedUtc: previous.CapturedUtc,
			Anomalies: anomalies,
			LedgerChainIntact: current.LedgerChainIntact,
			Message: message);
	}

	/// <summary>True when <paramref name="prefix"/> is a prefix of <paramref name="value"/> (and no longer
	/// than it). An empty prefix is a prefix of everything, which is the correct reading of "the store had no
	/// migration history at the baseline".</summary>
	private static bool IsPrefix(IReadOnlyList<string> prefix, IReadOnlyList<string> value)
	{
		if (prefix.Count > value.Count)
		{
			return false;
		}

		for (int index = 0; index < prefix.Count; index++)
		{
			if (!string.Equals(prefix[index], value[index], StringComparison.Ordinal))
			{
				return false;
			}
		}

		return true;
	}
}
