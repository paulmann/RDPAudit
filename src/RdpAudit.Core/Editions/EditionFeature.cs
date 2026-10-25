/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : EditionFeature.cs
// Project: RdpAudit.Core (RdpAudit.Core.Editions)
// Purpose: The capabilities that are NOT part of the Community edition, one member per capability that
//          actually exists in the code base today. A member is added only when there is a real seam to
//          enforce it (a hosted service, a worker, a UI entry point) — a declared-but-unenforced
//          feature would be a licensing claim nobody checks.
// Depends: System
// Extends: Append new members at the END (the ordinal is mirrored into the IPC DTO) and declare their
//          minimum edition in EditionMatrix.MinimumFor.

namespace RdpAudit.Core.Editions;

/// <summary>A capability that a build either contains or does not.</summary>
/// <remarks>
/// Every member has an explicitly declared minimum edition. There is deliberately no "default allow":
/// asking for a feature that has no declared minimum throws, because an undeclared feature silently
/// becoming available is a licensing defect that no test would otherwise catch.
/// </remarks>
public enum EditionFeature
{
	/// <summary>The optional read-only HTTPS REST API listener (<c>ApiOptions.Enabled</c>).</summary>
	RestApi = 0,

	/// <summary>P4-18 cross-host correlation: the polling worker and its fact store.</summary>
	CrossHostCorrelation = 1,

	/// <summary>The Zabbix push channel and its provisioning commands.</summary>
	ZabbixIntegration = 2,

	/// <summary>SIEM export of per-IP evidence from the Configurator.</summary>
	SiemExport = 3,

	/// <summary>Response dry-run: the auto-block engine records what it would block and applies nothing.</summary>
	ResponseDryRun = 4,
}
