/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : StoreFingerprintChainVerdict.cs
// Project: RdpAudit.Core (RdpAudit.Core.Integrity)
// Purpose: The single place where a REPORTED store-fingerprint chain state becomes an operator-facing
//          verdict: the wire name, the short phrase and the escalation band. The Database tab's banner,
//          the Database-tab report and the Diagnostic tab all read their severity and wording from here,
//          so a tamper verdict cannot be worded or coloured two different ways on two tabs of the same
//          product.
//          Deliberately separate from StoreIntegritySeverity (which grades a start-up comparison finding
//          for the audit row and the marker): this type grades what a READER should do with a state that
//          was reported - including "nothing was reported at all", which StoreIntegritySeverity has no
//          member for and must not gain one, because an unread verdict is not a finding about the store.
// Depends: StoreFingerprintChainState
// Extends: A new chain state must be added to NameOf, Describe and BandOf in the same commit; BandOf is
//          fail-closed, so an unrecognised value escalates rather than washing out as a pass.

using System.Globalization;

namespace RdpAudit.Core.Integrity;

/// <summary>How loud a store-integrity verdict has to be, ordered by escalation. <see cref="Unknown"/> is
/// deliberately louder than <see cref="Ok"/>: a verdict that could not be read is exactly the case that
/// must never render as "all clear".</summary>
public enum StoreIntegrityVerdictBand
{
	/// <summary>The verdict was not reported at all (no overview, a partial one, a host without the
	/// fingerprint store, an explicit null). Not a pass.</summary>
	Unknown = 0,

	/// <summary>The chain verifies. The only band that may be shown in a neutral treatment.</summary>
	Ok = 1,

	/// <summary>A capture was cut short (B24). Reported, but it is not an accusation of tampering.</summary>
	Warning = 2,

	/// <summary>Recorded state is gone, unreadable, internally inconsistent, or the host reported a state
	/// this build does not recognise. Shown as an error.</summary>
	Error = 3,
}

/// <summary>Turns a reported fingerprint-chain state into the verdict every surface renders.</summary>
public static class StoreFingerprintChainVerdict
{
	/// <summary>The chain verifies against its sealed tip.</summary>
	public const string Ok = "ok";

	/// <summary>Entries the sealed tip accounts for are not on disk.</summary>
	public const string Missing = "missing";

	/// <summary>An entry or the sealed tip exists but could not be read, parsed or unsealed.</summary>
	public const string Unreadable = "unreadable";

	/// <summary>The records contradict each other or the sealed tip in the "replaced / rolled back"
	/// direction.</summary>
	public const string ChainBroken = "chain-broken";

	/// <summary>A capture was cut short; corroborated by a durable write intent (B24).</summary>
	public const string Interrupted = "interrupted";

	/// <summary>Reported by a host that could read only the pre-B19 fingerprint document, so the chain
	/// itself was never verified. A limitation to show, never a pass.</summary>
	public const string Unverified = "unverified";

	/// <summary>The wire name of a chain state, exactly as it travels in the DTOs.</summary>
	public static string NameOf(StoreFingerprintChainState state) => state switch
	{
		StoreFingerprintChainState.Ok => Ok,
		StoreFingerprintChainState.Missing => Missing,
		StoreFingerprintChainState.Unreadable => Unreadable,
		StoreFingerprintChainState.ChainBroken => ChainBroken,
		StoreFingerprintChainState.Interrupted => Interrupted,
		_ => state.ToString().ToLowerInvariant(),
	};

	/// <summary>The escalation band of a REPORTED state. Null or blank means nothing was reported, which is
	/// <see cref="StoreIntegrityVerdictBand.Unknown"/> and never <see cref="StoreIntegrityVerdictBand.Ok"/>;
	/// an unrecognised value is an error, not a neutral reading (fail closed).</summary>
	public static StoreIntegrityVerdictBand BandOf(string? reportedState)
	{
		if (string.IsNullOrWhiteSpace(reportedState))
		{
			return StoreIntegrityVerdictBand.Unknown;
		}

		if (string.Equals(reportedState, Ok, StringComparison.OrdinalIgnoreCase))
		{
			return StoreIntegrityVerdictBand.Ok;
		}

		return string.Equals(reportedState, Interrupted, StringComparison.OrdinalIgnoreCase)
			? StoreIntegrityVerdictBand.Warning
			: StoreIntegrityVerdictBand.Error;
	}

	/// <summary>True when the band forbids the neutral treatment.</summary>
	public static bool BandIsAlarming(StoreIntegrityVerdictBand band) => band != StoreIntegrityVerdictBand.Ok;

	/// <summary>True when a verdict was actually OBTAINED. A state string on its own is not enough: a snapshot
	/// that failed outright, or one whose verdict section did not complete, carries no reading no matter what
	/// its fields happen to hold. Every surface that renders the verdict decides with this, so the Database tab
	/// and the Diagnostic tab cannot disagree about whether there is a verdict to show.</summary>
	/// <param name="snapshotSucceeded">The producer reported a Success status for the snapshot.</param>
	/// <param name="verdictSectionCompleted">The snapshot lists a COMPLETED section that produces the
	/// verdict (the integrity read timed out or failed otherwise).</param>
	/// <param name="reportedState">The state field as received, or null.</param>
	public static bool WasReported(
		bool snapshotSucceeded,
		bool verdictSectionCompleted,
		string? reportedState) =>
		snapshotSucceeded && verdictSectionCompleted && !string.IsNullOrWhiteSpace(reportedState);

	/// <summary>The band to render for a possibly-absent verdict: the state's own band when it was reported,
	/// otherwise <see cref="StoreIntegrityVerdictBand.Unknown"/>. Never <see cref="StoreIntegrityVerdictBand.Ok"/>
	/// for a verdict that was not obtained.</summary>
	public static StoreIntegrityVerdictBand BandForReport(
		bool snapshotSucceeded,
		bool verdictSectionCompleted,
		string? reportedState) =>
		WasReported(snapshotSucceeded, verdictSectionCompleted, reportedState)
			? BandOf(reportedState)
			: StoreIntegrityVerdictBand.Unknown;

	/// <summary>The sentence for a verdict that was never reported, naming why it was not. One phrasing for
	/// every surface, so "we could not read it" reads the same wherever the operator meets it.</summary>
	public static string DescribeNotReported(string reason) =>
		"UNKNOWN - no fingerprint-chain verdict was obtained (" + reason + "), so the tamper evidence of this "
		+ "store was NOT verified. This is not a pass.";

	/// <summary>One stable phrase per state, for a banner and for a report line. The state is always named
	/// as reported as well, so a reader who saw the log line finds the same word on screen.</summary>
	public static string Describe(string? reportedState) => BandOf(reportedState) switch
	{
		StoreIntegrityVerdictBand.Unknown => DescribeNotReported("no state was reported"),
		StoreIntegrityVerdictBand.Ok =>
			"The store-fingerprint chain verifies. No recorded state is missing and no capture was cut short.",
		_ when string.Equals(reportedState, Interrupted, StringComparison.OrdinalIgnoreCase) =>
			"A capture was cut short (a crash or a power loss between appending an entry and re-sealing the "
			+ "tip). Nothing already recorded is missing; the next capture re-seals the tip.",
		_ when string.Equals(reportedState, Missing, StringComparison.OrdinalIgnoreCase) =>
			"The store-fingerprint chain is MISSING entries the sealed tip accounts for: fingerprints that "
			+ "were recorded are no longer on disk.",
		_ when string.Equals(reportedState, Unreadable, StringComparison.OrdinalIgnoreCase) =>
			"The store-fingerprint chain could not be read: an entry or the sealed tip exists but could not "
			+ "be parsed or unsealed.",
		_ when string.Equals(reportedState, ChainBroken, StringComparison.OrdinalIgnoreCase) =>
			"The store-fingerprint chain is BROKEN: its records contradict each other or the sealed tip, so "
			+ "the baseline was replaced or rolled back.",
		_ when string.Equals(reportedState, Unverified, StringComparison.OrdinalIgnoreCase) =>
			"The store-fingerprint chain was NOT verified: this host read only the pre-B19 fingerprint "
			+ "document, so the chain state is unverified rather than intact.",
		_ => string.Format(
			CultureInfo.InvariantCulture,
			"The store-fingerprint chain reported an unrecognised state '{0}'; treat it as an integrity "
			+ "failure until it is explained.",
			reportedState),
	};

	/// <summary>A short label for the state as reported, for a banner's first line. Null or blank becomes
	/// <c>unknown</c>, never <c>ok</c>.</summary>
	public static string LabelOf(string? reportedState) =>
		string.IsNullOrWhiteSpace(reportedState) ? "unknown" : reportedState!;
}
