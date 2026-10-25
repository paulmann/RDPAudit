// File:    src/RdpAudit.Core/CrossHost/CrossHostFactModel.cs
// Module:  RdpAudit.Core.CrossHost
// Purpose: Pure in-memory domain model for cross-host correlation: fact projections exported by
//          agent hosts (AuthAttemptFact summaries - never raw event XML), a per-host availability
//          view, and the deterministic outcome a correlation pass reports. Kept free of EF Core,
//          SQLite and any I/O so the correlation engine and its tests run on any host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.CrossHost;

/// <summary>Classification of one cross-host fact link. Ordinals are in-memory only (never persisted
/// directly); the persisted projection reuses this kind via its integer column.</summary>
public enum CrossHostFactKind
{
	/// <summary>Default sentinel - must never be correlated.</summary>
	Unknown = 0,

	/// <summary>Failed authentication (Security 4625-class outcome).</summary>
	FailedLogon = 1,

	/// <summary>Successful authentication (Security 4624-class outcome).</summary>
	SuccessfulLogon = 2,

	/// <summary>Privileged logon (Security 4672-class outcome, SeDebug / SeTcb assignment).</summary>
	PrivilegedLogon = 3,
}

/// <summary>Operational availability of one agent host as seen by the correlation worker.</summary>
public enum CrossHostAvailability
{
	/// <summary>Host responded and supplied facts during the last poll.</summary>
	Available = 0,

	/// <summary>Host could not be reached or supplied malformed data. Fail-closed: no facts are
	/// invented for an unavailable host.</summary>
	Unavailable = 1,

	/// <summary>Host is configured but has never been polled yet.</summary>
	Unknown = 2,
}

/// <summary>
/// In-memory projection of one authentication fact contributed by a host. This is the ONLY shape
/// the correlation engine consumes: agent hosts export summaries (event id-derived kind, normalized
/// user, host-qualified time), never XML bodies. All fields are validated by
/// <see cref="CrossHostFactProjection.IsValid"/> at the trust boundary.
/// </summary>
public sealed class CrossHostFactProjection
{
	/// <summary>Agent host this fact was observed on. Never empty after validation.</summary>
	public string HostName { get; set; } = string.Empty;

	/// <summary>UTC observation time from the originating Windows event.</summary>
	public DateTime TimeUtc { get; set; }

	/// <summary>Attempted / authenticated user name.</summary>
	public string? UserName { get; set; }

	/// <summary>Canonical user key (lower-case, domain-stripped) used for cross-host joining.</summary>
	public string? NormalizedUserName { get; set; }

	/// <summary>Source IP, when known.</summary>
	public string? SourceIp { get; set; }

	/// <summary>Windows logon type, when known.</summary>
	public int? LogonType { get; set; }

	/// <summary>Classification of this fact as a chain-link candidate.</summary>
	public CrossHostFactKind Kind { get; set; }

	/// <summary>Originating Windows event id (4624 / 4625 / 4672).</summary>
	public int EventId { get; set; }

	/// <summary>Stable deduplication key computed by the exporter (SHA-256 hex of the canonical
	/// field set). The engine treats facts with an equal key as the same observation.</summary>
	public string? DedupKey { get; set; }

	/// <summary>Returns true when this projection passes all trust-boundary checks. HostName must
	/// be non-blank and bounded, TimeUtc must not be the default or an obvious extreme future
	/// value, the user key must be present for correlatable kinds, and Kind != Unknown.</summary>
	public bool IsValid()
	{
		if (string.IsNullOrWhiteSpace(HostName) || HostName.Length > 256)
		{
			return false;
		}

		if (TimeUtc == default || TimeUtc.Kind == DateTimeKind.Unspecified || TimeUtc.Year < 2000 || TimeUtc.Year > 2200)
		{
			return false;
		}

		if (Kind == CrossHostFactKind.Unknown)
		{
			return false;
		}

		if (string.IsNullOrWhiteSpace(NormalizedUserName) || NormalizedUserName.Length > 256)
		{
			return false;
		}

		if (EventId <= 0)
		{
			return false;
		}

		return true;
	}

	/// <summary>Builds the stable deduplication key for this projection when the exporter did not
	/// supply one. The key covers host, canonicalized time (millisecond precision, UTC), user, kind
	/// and event id so a re-pull of the same fact never creates a second row while two distinct
	/// facts in the same second (e.g. two failed logons during a spray) stay distinct.</summary>
	public string BuildDedupKey()
	{
		string canonical = string.Format(
			CultureInfo.InvariantCulture,
			"{0}|{1:yyyyMMddHHmmssfff}|{2}|{3}|{4}",
			HostName.Trim().ToLowerInvariant(),
			TimeUtc.ToUniversalTime(),
			(NormalizedUserName ?? string.Empty).ToLowerInvariant(),
			(int)Kind,
			EventId);
		return CrossHostStableHash.Compute(canonical);
	}
}

/// <summary>Immutable availability view of one host for a correlation pass.</summary>
public sealed class CrossHostAvailabilityView
{
	public CrossHostAvailabilityView(string hostName, CrossHostAvailability availability, DateTime? lastSeenUtc, string? lastError)
	{
		HostName = hostName;
		Availability = availability;
		LastSeenUtc = lastSeenUtc;
		LastError = lastError;
	}

	public string HostName { get; }

	public CrossHostAvailability Availability { get; }

	public DateTime? LastSeenUtc { get; }

	public string? LastError { get; }
}

/// <summary>Outcome reported by a single correlation pass. Deterministic and free of EF types.</summary>
public sealed class CrossHostCorrelationResult
{
	public List<CrossHostChainCandidate> Chains { get; } = new();

	public int FactsAccepted { get; set; }

	public int FactsRejected { get; set; }

	public int FactsDuplicated { get; set; }
}

/// <summary>One fully-eligible attack chain produced by the engine.</summary>
public sealed class CrossHostChainCandidate
{
	public string RuleId { get; set; } = string.Empty;

	public string ChainKey { get; set; } = string.Empty;

	public string NormalizedUserName { get; set; } = string.Empty;

	public List<CrossHostChainLinkCandidate> Links { get; } = new();

	public DateTime FirstSeenUtc { get; set; }

	public DateTime LastSeenUtc { get; set; }

	/// <summary>Risk score computed by the rule (0..100).</summary>
	public int Score { get; set; }

	/// <summary>Number of failed-login facts that fed the first link.</summary>
	public int FailedAttemptCount { get; set; }
}

/// <summary>One link (hop) of an eligible chain. Each hop names its host so the UI can render
/// host -&gt; host -&gt; host transitions without any further lookup.</summary>
public sealed class CrossHostChainLinkCandidate
{
	public string HostName { get; set; } = string.Empty;

	public CrossHostFactKind Kind { get; set; }

	public int EventId { get; set; }

	public DateTime TimeUtc { get; set; }

	public string? SourceIp { get; set; }

	public string? UserName { get; set; }
}
