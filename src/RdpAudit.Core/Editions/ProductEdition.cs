/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ProductEdition.cs
// Project: RdpAudit.Core (RdpAudit.Core.Editions)
// Purpose: The commercial editions of the product, ordered by capability. The ordinal is part of the
//          IPC surface (EditionInfoDto.EditionOrdinal) and of the licence audit trail, so it is an
//          append-only value: new editions are added at the END with the next free number.
// Depends: System
// Extends: Add a new edition at the end of the enum, extend EditionMatrix with its minimums and
//          limits, and add a matching RDPAUDIT_EDITION_* constant in Directory.Build.props.

namespace RdpAudit.Core.Editions;

/// <summary>
/// The edition a given build belongs to. Ordered: a build of a higher edition contains every
/// capability of the lower ones.
/// </summary>
/// <remarks>
/// The value is chosen at COMPILE time (see <see cref="EditionContext"/>) so an edition cannot be
/// upgraded by editing a configuration file or a registry value: the gated components are simply not
/// part of the composition of a lower edition. This is a licensing boundary, not a security
/// boundary — the binary is the licensed artefact.
/// </remarks>
public enum ProductEdition
{
	/// <summary>Free edition: local detection, local SQLite store, Windows Firewall response, one
	/// MikroTik router and the WinForms Configurator. No fleet, integration or REST surface.</summary>
	Community = 0,

	/// <summary>Adds the read-only REST API, cross-host correlation, SIEM export, the Zabbix push
	/// channel and the dry-run response policy.</summary>
	Pro = 1,

	/// <summary>Adds the enterprise surface: a larger cross-host fleet budget plus the capabilities
	/// reserved for it (RBAC/SSO, HA collector, compliance reporting).</summary>
	Enterprise = 2,
}
