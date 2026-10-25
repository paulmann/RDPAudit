/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionPolicyOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Information-density retention policy - the pressure rules that bound the size of the
//          raw-event detail table while keeping the information-poor duplicates as the only
//          compressible rows. Every bound resolves through a clamped Resolve* helper so a hand-edited
//          appsettings.json can never widen a limit beyond the supported range. Disabled by default:
//          with Enabled=false the service behaves exactly as it did before this policy existed.
// Depends: System, RetentionAnchorScope
// Extends: Add a new pressure trigger here together with its Resolve* clamp and its matching
//          EventDeletionTrigger ordinal.

using System.Globalization;

namespace RdpAudit.Core.Config;

/// <summary>
/// Settings for the optional information-density retention pass. The pass deletes only rows that
/// carry the least unique information - the interior of the densest event codes, never the anchor
/// (oldest record of a code) and never the protected tail (newest records of a code) - and records
/// every deleted window in <c>EventDeletionLedger</c> so removed evidence is never indistinguishable
/// from absent activity.
/// </summary>
public sealed class RetentionPolicyOptions
{
	// ── Supported bounds ─────────────────────────────────────────────────────────

	/// <summary>Smallest effective protected-tail length. Zero would let the pass delete the newest
	/// record of a code, which is the live investigation window.</summary>
	public const int MinTailKeepPerCode = 1;

	/// <summary>Largest effective protected-tail length. Above this "keep everything" describes the
	/// setting more honestly than "keep a tail".</summary>
	public const int MaxTailKeepPerCode = 100_000;

	/// <summary>Smallest effective candidate threshold. A code stream with fewer than this many rows
	/// in the deletion window carries too little redundancy to be worth compressing.</summary>
	public const int MinCandidateMinRows = 10;

	/// <summary>Largest effective candidate threshold.</summary>
	public const int MaxCandidateMinRows = 100_000_000;

	/// <summary>Smallest effective age floor in days. Zero would allow the pass to delete rows that
	/// were ingested minutes ago, while an investigator may still be reading them.</summary>
	public const int MinMinAgeDays = 1;

	/// <summary>Largest effective age floor in days (ten years).</summary>
	public const int MaxMinAgeDays = 3_650;

	/// <summary>Smallest effective per-pass deletion budget.</summary>
	public const int MinMaxRowsPerPass = 1;

	/// <summary>Largest effective per-pass deletion budget. Bounds the work one tick may do.</summary>
	public const int MaxMaxRowsPerPass = 10_000_000;

	/// <summary>Smallest effective writer-lock budget in milliseconds.</summary>
	public const int MinMaxWriterLockMs = 10;

	/// <summary>Largest effective writer-lock budget in milliseconds.</summary>
	public const int MaxMaxWriterLockMs = 60_000;

	/// <summary>Smallest effective rows-per-delete-statement batch.</summary>
	public const int MinDeleteBatchRows = 100;

	/// <summary>Largest effective rows-per-delete-statement batch. Keeps one writer-lock section
	/// short on very large databases.</summary>
	public const int MaxDeleteBatchRows = 100_000;

	/// <summary>
	/// Event codes that are never eligible for pressure deletion regardless of their row count:
	/// account changes, service installation, privilege / token anomalies, Kerberos attack signals
	/// and the logon-classification codes an attacker would most like to have compressed away.
	/// Order is documentation-only; membership is what matters.
	/// </summary>
	public static readonly int[] DefaultProtectedEventIds =
	[
		4672, // Special privileges assigned to new logon
		4673, // Privileged service called
		4674, // Operation attempted on a privileged object
		4697, // A service was installed in the system
		4720, // A user account was created
		4722, // A user account was enabled
		4723, // An attempt was made to change an account's password
		4724, // An attempt was made to reset an account's password
		4728, // A member was added to a security-enabled global group
		4732, // A member was added to a security-enabled local group
		4756, // A member was added to a security-enabled universal group
		4769, // A Kerberos service ticket was requested
		4771, // Kerberos pre-authentication failed
		7045, // A new service was installed (System channel)
	];

	// ── Master switches ──────────────────────────────────────────────────────────

	/// <summary>Master switch for the information-density retention pass. Defaults to false: existing
	/// installations behave exactly as before until an operator explicitly opts in.</summary>
	public bool Enabled { get; set; }

	/// <summary>Legal hold. When true the pressure rules are inert - no trigger is evaluated and no
	/// row is deleted - so an operator can freeze the store for an investigation or a legal request.
	/// Defaults to false.</summary>
	public bool LegalHold { get; set; }

	// ── Anchor scope and protected classes ───────────────────────────────────────

	/// <summary>Code granularity. Defaults to <see cref="RetentionAnchorScope.PerCode"/>.</summary>
	public RetentionAnchorScope AnchorScope { get; set; } = RetentionAnchorScope.PerCode;

	/// <summary>Event codes that are never candidates for pressure deletion. An empty or missing list
	/// resolves back to <see cref="DefaultProtectedEventIds"/>, so clearing the JSON array cannot
	/// silently disarm the anti-anti-forensics protection. Defaults to the full protected set.</summary>
	public int[] ProtectedEventIds { get; set; } = [.. DefaultProtectedEventIds];

	// ── Interior selection ───────────────────────────────────────────────────────

	/// <summary>Number of newest records of each code that are never deleted. Defaults to 512;
	/// clamped to [1, 100,000].</summary>
	public int TailKeepPerCode { get; set; } = 512;

	/// <summary>Minimum number of eligible rows a code must hold inside the deletion window before it
	/// becomes a candidate. Defaults to 1,000; clamped to [10, 100,000,000].</summary>
	public int CandidateMinRows { get; set; } = 1_000;

	/// <summary>Rows newer than this many days are never candidates. Defaults to 7; clamped to
	/// [1, 3,650].</summary>
	public int MinAgeDays { get; set; } = 7;

	/// <summary>Maximum number of rows one pass may delete across all codes. Defaults to 50,000;
	/// clamped to [1, 10,000,000].</summary>
	public int MaxRowsPerPass { get; set; } = 50_000;

	/// <summary>Maximum time one batch may hold the SQLite writer lock before the pass yields and
	/// defers the rest to the next tick. Defaults to 250; clamped to [10, 60,000].</summary>
	public int MaxWriterLockMs { get; set; } = 250;

	/// <summary>Rows removed by one delete statement. Bounds the size of a single writer-lock
	/// section. Defaults to 2,000; clamped to [100, 100,000].</summary>
	public int DeleteBatchRows { get; set; } = 2_000;

	// ── Pressure triggers (0 = the trigger is disabled) ──────────────────────────

	/// <summary>Database-file ceiling in bytes (database plus WAL plus shared-memory file).
	/// 0 disables the trigger. Defaults to 0.</summary>
	public long MaxDatabaseBytes { get; set; }

	/// <summary>Row ceiling for the <c>RawEvents</c> detail table. 0 disables the trigger.
	/// Defaults to 0.</summary>
	public long MaxRawEventRows { get; set; }

	/// <summary>Free-space floor in bytes on the volume(s) hosting the database and the shard tree.
	/// 0 disables the trigger. Defaults to 0.</summary>
	public long MinFreeDiskBytes { get; set; }

	// ── Clamped resolution ───────────────────────────────────────────────────────

	/// <summary>Returns <see cref="TailKeepPerCode"/> clamped to the supported range.</summary>
	public int ResolveTailKeepPerCode() => Math.Clamp(TailKeepPerCode, MinTailKeepPerCode, MaxTailKeepPerCode);

	/// <summary>Returns <see cref="CandidateMinRows"/> clamped to the supported range.</summary>
	public int ResolveCandidateMinRows() => Math.Clamp(CandidateMinRows, MinCandidateMinRows, MaxCandidateMinRows);

	/// <summary>Returns <see cref="MinAgeDays"/> clamped to the supported range.</summary>
	public int ResolveMinAgeDays() => Math.Clamp(MinAgeDays, MinMinAgeDays, MaxMinAgeDays);

	/// <summary>Returns <see cref="MaxRowsPerPass"/> clamped to the supported range.</summary>
	public int ResolveMaxRowsPerPass() => Math.Clamp(MaxRowsPerPass, MinMaxRowsPerPass, MaxMaxRowsPerPass);

	/// <summary>Returns <see cref="MaxWriterLockMs"/> clamped to the supported range.</summary>
	public int ResolveMaxWriterLockMs() => Math.Clamp(MaxWriterLockMs, MinMaxWriterLockMs, MaxMaxWriterLockMs);

	/// <summary>Returns <see cref="DeleteBatchRows"/> clamped to the supported range.</summary>
	public int ResolveDeleteBatchRows() => Math.Clamp(DeleteBatchRows, MinDeleteBatchRows, MaxDeleteBatchRows);

	/// <summary>Returns <see cref="MaxDatabaseBytes"/> clamped to zero or above; zero means the
	/// trigger is disabled.</summary>
	public long ResolveMaxDatabaseBytes() => Math.Max(0L, MaxDatabaseBytes);

	/// <summary>Returns <see cref="MaxRawEventRows"/> clamped to zero or above; zero means the
	/// trigger is disabled.</summary>
	public long ResolveMaxRawEventRows() => Math.Max(0L, MaxRawEventRows);

	/// <summary>Returns <see cref="MinFreeDiskBytes"/> clamped to zero or above; zero means the
	/// trigger is disabled.</summary>
	public long ResolveMinFreeDiskBytes() => Math.Max(0L, MinFreeDiskBytes);

	/// <summary>Returns <see cref="AnchorScope"/>, falling back to <see cref="RetentionAnchorScope.PerCode"/>
	/// when the configured value is not a defined enum member (a hand-edited numeric override cannot
	/// widen the anchor count silently).</summary>
	public RetentionAnchorScope ResolveAnchorScope()
		=> Enum.IsDefined(AnchorScope) ? AnchorScope : RetentionAnchorScope.PerCode;

	/// <summary>Returns the effective protected event codes as a set. A null or empty configured array
	/// resolves to <see cref="DefaultProtectedEventIds"/> so protection can never be disarmed by an
	/// empty JSON array.</summary>
	public HashSet<int> ResolveProtectedEventIds()
	{
		int[] configured = ProtectedEventIds is { Length: > 0 } ? ProtectedEventIds : DefaultProtectedEventIds;
		HashSet<int> codes = new(configured.Length);
		foreach (int code in configured)
		{
			if (code > 0)
			{
				codes.Add(code);
			}
		}

		return codes.Count > 0 ? codes : [.. DefaultProtectedEventIds];
	}

	/// <summary>True when the pressure rules may run at all: the policy is enabled and no legal hold
	/// is in force.</summary>
	public bool IsPressureDeletionAllowed() => Enabled && !LegalHold;

	/// <summary>True when at least one pressure trigger carries a positive ceiling. Used to report an
	/// honest "enabled but nothing to trigger on" skip instead of a silent no-op.</summary>
	public bool HasAnyPressureTrigger()
		=> ResolveMaxDatabaseBytes() > 0 || ResolveMaxRawEventRows() > 0 || ResolveMinFreeDiskBytes() > 0;

	/// <summary>Human-readable summary of the effective policy for operator logs.</summary>
	public string Describe()
		=> string.Create(
			CultureInfo.InvariantCulture,
			$"Enabled={Enabled} LegalHold={LegalHold} Scope={ResolveAnchorScope()} TailKeepPerCode={ResolveTailKeepPerCode()} CandidateMinRows={ResolveCandidateMinRows()} MinAgeDays={ResolveMinAgeDays()} MaxRowsPerPass={ResolveMaxRowsPerPass()} MaxWriterLockMs={ResolveMaxWriterLockMs()} DeleteBatchRows={ResolveDeleteBatchRows()} MaxDatabaseBytes={ResolveMaxDatabaseBytes()} MaxRawEventRows={ResolveMaxRawEventRows()} MinFreeDiskBytes={ResolveMinFreeDiskBytes()} ProtectedCodes={ResolveProtectedEventIds().Count}");
}
