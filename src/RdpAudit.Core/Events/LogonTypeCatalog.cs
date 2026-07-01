// File:    src/RdpAudit.Core/Events/LogonTypeCatalog.cs
// Module:  RdpAudit.Core.Events
// Purpose: Pure, UI-free catalog that decodes a Windows Security "Logon Type" numeric code
//          (as carried in Security 4624 / 4625 events) into an operator-friendly name and a
//          one-line human-readable description. Used by the Configurator to render the
//          "Last LogonType" cell hover tooltip and by exporters that annotate raw codes.
// Depends: (none — plain static maps over int codes)
// Extends: To add or correct a logon type, add a new entry to the Entries dictionary below;
//          keep the numeric code, short Name and long Description in sync with the MS docs
//          (see "Audit Logon" / Event 4624 documentation).
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.ObjectModel;
using System.Globalization;

namespace RdpAudit.Core.Events;

/// <summary>One decoded Windows logon type: numeric code, short name, and long description.</summary>
public readonly record struct LogonTypeInfo(int Code, string Name, string Description);

/// <summary>
/// Decodes Windows Security "Logon Type" codes (Event 4624 / 4625) into human-readable text.
/// The catalog is authoritative for the small, well-known set defined by Windows and never
/// throws for an unknown code — it returns a graceful "Unknown / vendor-specific" fallback.
/// </summary>
public static class LogonTypeCatalog
{
	// ── Data ─────────────────────────────────────────────────────────────────────
	// Canonical Windows logon types. Codes 1 and 6 are intentionally reserved by Windows
	// and are not emitted in practice; they are included so a raw code still decodes cleanly.
	private static readonly IReadOnlyDictionary<int, LogonTypeInfo> Entries =
		new ReadOnlyDictionary<int, LogonTypeInfo>(new Dictionary<int, LogonTypeInfo>
		{
			[0] = new(0, "System",
				"Used only by the local System account. Not a real interactive or network logon; "
				+ "some channels emit 0 when the type field is absent."),
			[1] = new(1, "Reserved",
				"Reserved by Windows and not used in practice."),
			[2] = new(2, "Interactive",
				"A user logged on at this computer directly (local console, keyboard, KVM) or via "
				+ "some remote tools that impersonate an interactive session."),
			[3] = new(3, "Network",
				"A user or service authenticated to this computer over the network (SMB file shares, "
				+ "IIS, NLA pre-authentication for RDP, service-to-service). Credentials are validated "
				+ "but no interactive desktop is created. Most brute-force noise appears here."),
			[4] = new(4, "Batch",
				"A batch/scheduled-task logon (Task Scheduler). Runs without an interactive user present."),
			[5] = new(5, "Service",
				"A Windows service started by the Service Control Manager under its configured account."),
			[6] = new(6, "Reserved",
				"Reserved by Windows and not used in practice."),
			[7] = new(7, "Unlock",
				"A workstation was unlocked (screen-saver / lock screen dismissed). For RDP this is "
				+ "typically a reconnect to an existing session."),
			[8] = new(8, "NetworkCleartext",
				"A network logon where the password was sent in clear text (e.g. Basic auth over IIS). "
				+ "Usually indicates a weakly configured endpoint."),
			[9] = new(9, "NewCredentials",
				"A caller cloned its token and specified new credentials for outbound connections only "
				+ "(RunAs /netonly). Local identity is unchanged; often seen with lateral-movement tooling."),
			[10] = new(10, "RemoteInteractive",
				"A full interactive Remote Desktop (RDP / Terminal Services / Remote Assistance) logon. "
				+ "This is the definitive signal that an actual RDP desktop session was established."),
			[11] = new(11, "CachedInteractive",
				"An interactive logon validated against locally cached domain credentials because a "
				+ "domain controller was unreachable."),
			[12] = new(12, "CachedRemoteInteractive",
				"A RemoteInteractive (RDP) logon validated against locally cached credentials."),
			[13] = new(13, "CachedUnlock",
				"A workstation unlock validated against locally cached credentials."),
		});

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Returns the decoded <see cref="LogonTypeInfo"/> for a code, or a graceful
	/// "Unknown / vendor-specific" fallback for codes outside the well-known Windows set.</summary>
	public static LogonTypeInfo Describe(int code) =>
		Entries.TryGetValue(code, out LogonTypeInfo info)
			? info
			: new LogonTypeInfo(
				code,
				"Unknown",
				"Unknown or vendor-specific logon type. Not part of the standard Windows set (0-13).");

	/// <summary>Returns a compact one-line label such as "3 — Network: A user or service …".
	/// Suitable for a DataGridView cell tooltip. Never returns null.</summary>
	public static string DescribeInline(int? code)
	{
		if (code is null)
		{
			return "Last LogonType: not available — no successful logon has been recorded for this IP yet.";
		}

		LogonTypeInfo info = Describe(code.Value);
		return string.Format(
			CultureInfo.InvariantCulture,
			"Logon Type {0} — {1}: {2}",
			info.Code,
			info.Name,
			info.Description);
	}

	/// <summary>Returns just the short name for a code, e.g. "RemoteInteractive". Never null.</summary>
	public static string NameOf(int code) => Describe(code).Name;
}
