/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StorageIntegrityOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Governs the scheduled integrity checks and the store fingerprint. The light daily quick_check is
//          on by default because it is read-only, cheap and its entire value is that it runs without an
//          operator asking; the full integrity_check is OFF by default because on a multi-gigabyte store it
//          reads every page and the operator must opt into that cost deliberately, inside a maintenance
//          window they choose.
//          Every switch here is observational: no code path repairs, truncates or rebuilds the store from a
//          check result. A detected problem is reported and nothing else.
// Depends: none
// Extends: Add a new scheduled check here together with its DatabaseIntegrityCheckKind ordinal, its
//          clamp and its entry in docs/40-options.md.

namespace RdpAudit.Core.Config;

/// <summary>Scheduled integrity-check cadence for the evidence store.</summary>
public sealed class StorageIntegrityOptions
{
	/// <summary>Bounds for <see cref="FullCheckIntervalDays"/>.</summary>
	public const int MinFullCheckIntervalDays = 1;

	/// <summary>Upper bound for <see cref="FullCheckIntervalDays"/>.</summary>
	public const int MaxFullCheckIntervalDays = 365;

	/// <summary>Enables the fingerprint capture/verification and the scheduled checks. Disabling it turns
	/// tamper evidence off entirely, which is why it defaults to true: the fingerprint is cheap (counts and
	/// one small ledger scan) and reporting an anomaly changes no data.</summary>
	public bool Enabled { get; set; } = true;

	/// <summary>Run a bounded <c>PRAGMA quick_check</c> once per day. Read-only and structurally cheap:
	/// SQLite walks the B-tree without verifying every page against its checksum.</summary>
	public bool QuickCheckEnabled { get; set; } = true;

	/// <summary>Run a full <c>PRAGMA integrity_check</c> inside the maintenance window. Off by default
	/// because it reads the whole file - minutes on a multi-gigabyte store - and the operator should choose
	/// when that cost is acceptable.</summary>
	public bool FullCheckEnabled { get; set; }

	/// <summary>Days between full integrity checks. Clamped to
	/// [<see cref="MinFullCheckIntervalDays"/>, <see cref="MaxFullCheckIntervalDays"/>].</summary>
	public int FullCheckIntervalDays { get; set; } = 7;

	/// <summary>Local hour at which the maintenance window opens. A full check only starts inside the
	/// window, so a long page-by-page read lands where the operator decided it should. Clamped to 0..23.</summary>
	public int MaintenanceWindowStartHourLocal { get; set; } = 3;

	/// <summary>Length of the maintenance window in hours. Clamped to 1..24.</summary>
	public int MaintenanceWindowDurationHours { get; set; } = 4;

	/// <summary>Runs <c>PRAGMA foreign_key_check</c> as part of the scheduled pass. Cheap relative to a full
	/// check and it catches referential damage that quick_check accepts.</summary>
	public bool ForeignKeyCheckEnabled { get; set; } = true;

	/// <summary>Returns <see cref="FullCheckIntervalDays"/> clamped to the supported range.</summary>
	public int ResolveFullCheckIntervalDays()
		=> Math.Clamp(FullCheckIntervalDays, MinFullCheckIntervalDays, MaxFullCheckIntervalDays);

	/// <summary>Returns <see cref="MaintenanceWindowStartHourLocal"/> clamped to a real hour of the day.</summary>
	public int ResolveMaintenanceWindowStartHourLocal() => Math.Clamp(MaintenanceWindowStartHourLocal, 0, 23);

	/// <summary>Returns <see cref="MaintenanceWindowDurationHours"/> clamped to 1..24.</summary>
	public int ResolveMaintenanceWindowDurationHours()
		=> Math.Clamp(MaintenanceWindowDurationHours, 1, 24);

	/// <summary>True when <paramref name="localNow"/> falls inside the configured maintenance window. A
	/// window that crosses midnight is handled by wrapping, because an operator who asks for 22:00 + 6 h
	/// means 22:00 to 04:00.</summary>
	public bool IsInsideMaintenanceWindow(DateTime localNow)
	{
		int start = ResolveMaintenanceWindowStartHourLocal();
		int duration = ResolveMaintenanceWindowDurationHours();
		int hour = localNow.Hour;
		int end = start + duration;
		return end <= 24
			? hour >= start && hour < end
			: hour >= start || hour < end - 24;
	}

	/// <summary>Human-readable summary of the effective cadence for operator logs.</summary>
	public string Describe()
		=> string.Create(
			System.Globalization.CultureInfo.InvariantCulture,
			$"Enabled={Enabled} QuickCheck={QuickCheckEnabled} FullCheck={FullCheckEnabled} "
				+ $"FullCheckIntervalDays={ResolveFullCheckIntervalDays()} "
				+ $"Window={ResolveMaintenanceWindowStartHourLocal():00}:00+{ResolveMaintenanceWindowDurationHours()}h(local) "
				+ $"ForeignKeyCheck={ForeignKeyCheckEnabled}");
}
