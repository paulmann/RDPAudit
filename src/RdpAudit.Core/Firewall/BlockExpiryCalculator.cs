// File:    src/RdpAudit.Core/Firewall/BlockExpiryCalculator.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: v1.3.9 — single source of truth for the ExpiresUtc of a newly created or updated block.
//          The Firewall tab showed "Never" for manual blacklist / Active block rows even when the
//          operator had configured a positive DefaultBlockDurationMinutes, because the manual-add IPC
//          path ignored that option and only honoured an explicit per-request duration. This pure
//          calculator centralises the precedence so the manual-add path, the auto-block worker and the
//          unit tests all agree: an explicit positive duration wins; otherwise the configured default
//          applies; a duration that resolves to exactly zero (no explicit, no default) means a
//          permanent block (ExpiresUtc == null → rendered "Never"). Pure / no I/O — fully testable.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Firewall;

/// <summary>Computes the expiry instant of a block from its creation time, an optional explicit
/// per-request duration, and the configured default block duration.</summary>
public static class BlockExpiryCalculator
{
	/// <summary>Resolves the effective block duration in minutes, applying the precedence
	/// explicit-request &gt; configured-default &gt; permanent. A non-positive value in BOTH inputs
	/// means a permanent block, signalled by a return of <c>0</c>.</summary>
	/// <param name="requestedDurationMinutes">The per-request duration the operator typed (0 = "use
	/// the configured default"; negative is treated the same as 0).</param>
	/// <param name="defaultDurationMinutes">The configured <c>DefaultBlockDurationMinutes</c> (0 or
	/// negative = permanent unless the request overrides it).</param>
	/// <returns>The positive number of minutes to apply, or <c>0</c> to indicate a permanent block.</returns>
	public static int ResolveDurationMinutes(int requestedDurationMinutes, int defaultDurationMinutes)
	{
		if (requestedDurationMinutes > 0)
		{
			return requestedDurationMinutes;
		}

		if (defaultDurationMinutes > 0)
		{
			return defaultDurationMinutes;
		}

		return 0;
	}

	/// <summary>Computes the ExpiresUtc for a block created/updated at <paramref name="addedUtc"/>.
	/// Returns <c>null</c> (permanent / "Never") when the resolved duration is non-positive; otherwise
	/// <paramref name="addedUtc"/> plus the resolved duration.</summary>
	public static DateTime? ComputeExpiresUtc(
		DateTime addedUtc,
		int requestedDurationMinutes,
		int defaultDurationMinutes)
	{
		int minutes = ResolveDurationMinutes(requestedDurationMinutes, defaultDurationMinutes);
		if (minutes <= 0)
		{
			return null;
		}

		return addedUtc.AddMinutes(minutes);
	}
}
