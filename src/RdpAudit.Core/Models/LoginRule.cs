// File:    src/RdpAudit.Core/Models/LoginRule.cs
// Module:  RdpAudit.Core.Models
// Purpose: Login trip-wire rule. Any attempted logon using a matching login name immediately
//          blocks the source IP. Use sparingly for honeypot logins such as `administrator` on a
//          host that does not use that account.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Login trip-wire rule: any attempted logon using a matching login blocks the source IP.</summary>
public sealed class LoginRule
{
	/// <summary>Auto-incremented surrogate key.</summary>
	public long Id { get; set; }

	/// <summary>Normalized matching key (typically the login folded to a case-insensitive form). This
	/// is what the trip-wire compares against; the operator-facing spelling lives in
	/// <see cref="DisplayLogin"/>. Comparison is case-insensitive.</summary>
	public string Login { get; set; } = string.Empty;

	/// <summary>Original login spelling as typed by the operator, preserved for display so the UI does
	/// not lower-case "Administrator" into "administrator". Falls back to <see cref="Login"/> when not
	/// set (legacy rows created before this column existed).</summary>
	public string? DisplayLogin { get; set; }

	/// <summary>Operator-supplied note explaining why this login is a trip-wire.</summary>
	public string? Note { get; set; }

	/// <summary>Soft-disable flag; disabled rows are retained for audit but not enforced.</summary>
	public bool Enabled { get; set; } = true;

	/// <summary>UTC timestamp when the rule was created.</summary>
	public DateTime AddedUtc { get; set; }

	/// <summary>Number of times this trip-wire has fired (incremented when an alert matches it).</summary>
	public long TriggerCount { get; set; }

	/// <summary>UTC timestamp of the first time this trip-wire fired; null until it has tripped once.</summary>
	public DateTime? FirstTriggeredUtc { get; set; }

	/// <summary>UTC timestamp of the most recent firing; null until it has tripped once.</summary>
	public DateTime? LastTriggeredUtc { get; set; }

	/// <summary>Source IP that most recently tripped this rule; null until it has tripped once.</summary>
	public string? LastSourceIp { get; set; }
}
