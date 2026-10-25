/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : SchemaCompatibility.cs
// Project: RdpAudit.Core (RdpAudit.Core.Backup)
// Purpose: The testable core of the downgrade guard. Given the migrations the database says were
//          applied and the migrations the running binaries know about, decide whether starting this
//          build against that database is allowed. This file is deliberately pure - no database, no
//          filesystem, no options - because it is the one decision that must never be wrong: an older
//          binary silently started against a newer schema is how a downgrade corrupts evidence.
//          Callers (AuditDbInitializer, the snapshot verifier) own the I/O and pass the two lists in.
// Depends: System.Globalization
// Extends: A new verdict must come with its own operator-actionable message here, because every
//          caller surfaces Message verbatim to the operator and the log.

using System.Globalization;

namespace RdpAudit.Core.Backup;

/// <summary>Outcome of comparing a database's applied migrations with the binaries' known ones.</summary>
public enum SchemaCompatibilityVerdict
{
	/// <summary>The database is at or behind the binaries. Migrating forward (or starting as-is) is
	/// allowed; the initializer applies whatever is pending.</summary>
	Compatible = 0,

	/// <summary>The database carries at least one migration the binaries do not know, so it was
	/// written by a newer build. Starting this build would operate on a schema it does not understand.</summary>
	DatabaseAheadOfBinaries = 1,

	/// <summary>The applied migration history could not be read at all (no history table, unreadable
	/// history). Distinct from an empty history, which is a normal new database.</summary>
	HistoryUnavailable = 2,

	/// <summary>The applied migration history contains an entry that cannot be a migration id, so the
	/// history itself is damaged and no compatibility judgement can be trusted.</summary>
	HistoryInvalid = 3,
}

/// <summary>Result of a schema compatibility evaluation, carrying the evidence for its verdict.</summary>
public sealed record SchemaCompatibilityResult(
	SchemaCompatibilityVerdict Verdict,
	IReadOnlyList<string> AppliedMigrations,
	IReadOnlyList<string> UnknownAppliedMigrations,
	string Message)
{
	/// <summary>True only for <see cref="SchemaCompatibilityVerdict.Compatible"/>.</summary>
	public bool IsCompatible => Verdict == SchemaCompatibilityVerdict.Compatible;

	/// <summary>True when the caller must refuse to touch the database.</summary>
	public bool MustRefuseStartup
		=> Verdict is SchemaCompatibilityVerdict.DatabaseAheadOfBinaries or SchemaCompatibilityVerdict.HistoryInvalid;
}

/// <summary>Pure comparison of a database's applied migrations against the binaries' migration list.</summary>
public static class SchemaCompatibility
{
	/// <summary>
	/// Evaluates whether <paramref name="knownByBinaries"/> can operate on a database whose history is
	/// <paramref name="appliedFromDatabase"/>.
	/// </summary>
	/// <param name="appliedFromDatabase">Migrations the database reports as applied, in apply order.
	/// Pass <see langword="null"/> only when the history could not be read at all - that is reported as
	/// <see cref="SchemaCompatibilityVerdict.HistoryUnavailable"/> and is not the same as an empty list,
	/// which is a brand new database and therefore compatible.</param>
	/// <param name="knownByBinaries">Migrations the running assemblies define. Required.</param>
	/// <param name="databasePath">Optional database path woven into the message so the operator knows
	/// which store the verdict is about.</param>
	public static SchemaCompatibilityResult Evaluate(
		IReadOnlyList<string>? appliedFromDatabase,
		IReadOnlyList<string> knownByBinaries,
		string? databasePath = null)
	{
		ArgumentNullException.ThrowIfNull(knownByBinaries);

		string target = string.IsNullOrWhiteSpace(databasePath) ? "the database" : "the database '" + databasePath + "'";

		if (appliedFromDatabase is null)
		{
			return new SchemaCompatibilityResult(
				SchemaCompatibilityVerdict.HistoryUnavailable,
				Array.Empty<string>(),
				Array.Empty<string>(),
				"The applied migration history of " + target + " could not be read, so schema compatibility cannot be proven.");
		}

		List<string> applied = [];
		List<string> invalid = [];
		foreach (string? migration in appliedFromDatabase)
		{
			if (string.IsNullOrWhiteSpace(migration))
			{
				invalid.Add(migration ?? "(null)");
				continue;
			}

			applied.Add(migration);
		}

		if (invalid.Count > 0)
		{
			return new SchemaCompatibilityResult(
				SchemaCompatibilityVerdict.HistoryInvalid,
				applied,
				Array.Empty<string>(),
				string.Format(
					CultureInfo.InvariantCulture,
					"The migration history of {0} contains {1} entry/entries that are not migration ids, so its schema state cannot be trusted. Restore a snapshot of this database or let the Configurator back it up and reset it.",
					target,
					invalid.Count));
		}

		if (applied.Count == 0)
		{
			return new SchemaCompatibilityResult(
				SchemaCompatibilityVerdict.Compatible,
				applied,
				Array.Empty<string>(),
				"No migration history exists in " + target + ", so it is treated as a new database.");
		}

		HashSet<string> known = new(knownByBinaries.Count, StringComparer.Ordinal);
		foreach (string? migration in knownByBinaries)
		{
			if (!string.IsNullOrWhiteSpace(migration))
			{
				known.Add(migration);
			}
		}

		List<string> unknown = [];
		foreach (string migration in applied)
		{
			if (!known.Contains(migration))
			{
				unknown.Add(migration);
			}
		}

		if (unknown.Count > 0)
		{
			return new SchemaCompatibilityResult(
				SchemaCompatibilityVerdict.DatabaseAheadOfBinaries,
				applied,
				unknown,
				string.Format(
					CultureInfo.InvariantCulture,
					"{0} has {1} applied migration(s) this build does not know ({2}). The database was created or upgraded by a newer RdpAudit build, so this build refuses to open it: downgrading the binaries is not supported. Install the build that created it, restore a snapshot taken before the upgrade, or let the Configurator back the database up and start from a fresh one.",
					target,
					unknown.Count,
					string.Join(", ", unknown)));
		}

		return new SchemaCompatibilityResult(
			SchemaCompatibilityVerdict.Compatible,
			applied,
			unknown,
			string.Format(
				CultureInfo.InvariantCulture,
				"{0} is compatible: {1} applied migration(s), all known to this build ({2} defined).",
				target,
				applied.Count,
				knownByBinaries.Count));
	}
}
