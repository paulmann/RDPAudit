// File:    src/RdpAudit.Core/ProcessMonitoring/KnownProcessKey.cs
// Module:  RdpAudit.Core.ProcessMonitoring
// Purpose: Pure, UI-free normalisation of the process-observation identity used by
//          NewProcessRule and KnownProcessStore. Produces the append-only baseline key
//          (ProcessName, ProcessUserCategory, UserName) from a RawEvent's ProcessName /
//          UserName / Domain fields: the exact lower-cased filename without path segments,
//          the system-vs-interactive category, and the normalized lower-cased
//          Domain\User identity (empty string for system processes, so the SQLite unique
//          index over (ProcessName, UserCategory, UserName) also deduplicates system
//          identities). Case and control-character sanitisation keep the persisted key
//          stable and bounded; detailed display strings stay in the alert Details JSON.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;
using RdpAudit.Core.Events;

namespace RdpAudit.Core.ProcessMonitoring;

/// <summary>Normalised baseline identity of one observed process.</summary>
public readonly record struct KnownProcessKey(
	string ProcessName,
	ProcessUserCategory UserCategory,
	string UserName)
{
	/// <summary>Maximum persisted process-name length (matches the Stage16 column width).</summary>
	public const int MaxProcessNameLength = 260;

	/// <summary>Maximum persisted normalized identity length (matches the Stage16 column width).</summary>
	public const int MaxUserNameLength = 256;

	/// <summary>Builds the baseline key from raw event fields. A blank process name yields an
	/// empty key (callers skip empty keys - they never reach the baseline store).</summary>
	public static KnownProcessKey Build(string? processName, string? userName, string? domain)
	{
		string name = SanitizeProcessName(processName);
		ProcessUserCategory category = ClassifyUserName(userName);
		string identity = category == ProcessUserCategory.Interactive
			? NormalizeIdentity(userName, domain)
			: string.Empty;
		return new KnownProcessKey(name, category, identity);
	}

	/// <summary>True when this key cannot be persisted (no process name).</summary>
	public bool IsEmpty => ProcessName.Length == 0;

	/// <summary>Extracts the exact lower-cased filename (no path segments), trims whitespace,
	/// strips control characters and caps the length. Returns an empty string for unusable input.
	/// Image-name based comparison is deliberately case-insensitive (NTFS semantics).</summary>
	public static string SanitizeProcessName(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return string.Empty;
		}

		string name = raw.Trim();
		int slash = Math.Max(name.LastIndexOf('\\'), name.LastIndexOf('/'));
		if (slash >= 0)
		{
			name = name[(slash + 1)..];
		}

		name = StripControlChars(name).Trim();
		if (name.Length == 0)
		{
			return string.Empty;
		}

		if (name.Length > MaxProcessNameLength)
		{
			name = name[..MaxProcessNameLength];
		}

		return name.ToLowerInvariant();
	}

	/// <summary>Classifies who runs the process. System covers empty/blank identities and the
	/// well-known Windows service / built-in / machine accounts decoded by
	/// <see cref="RdpServiceAccountCatalog"/> (SYSTEM, LOCAL SERVICE, NETWORK SERVICE,
	/// DWM-&lt;id&gt;, UMFD-&lt;id&gt;, name$); everything else is an interactive user.</summary>
	public static ProcessUserCategory ClassifyUserName(string? userName)
	{
		if (string.IsNullOrWhiteSpace(userName))
		{
			return ProcessUserCategory.System;
		}

		string name = userName.Trim();
		return RdpServiceAccountCatalog.IsServiceAccount(name)
			? ProcessUserCategory.System
			: ProcessUserCategory.Interactive;
	}

	/// <summary>Builds the normalized lower-cased <c>Domain\User</c> identity, stripping control
	/// characters and capping the length. An empty domain yields the bare user name.</summary>
	public static string NormalizeIdentity(string? userName, string? domain)
	{
		string user = StripControlChars((userName ?? string.Empty).Trim());
		string dom = StripControlChars((domain ?? string.Empty).Trim());
		string identity = dom.Length == 0 ? user : dom + "\\" + user;
		if (identity.Length > MaxUserNameLength)
		{
			identity = identity[..MaxUserNameLength];
		}

		return identity.ToLowerInvariant();
	}

	/// <summary>Removes control characters so persisted keys and alert payloads never carry
	/// terminal-control injection primitives (adversarial hardening - see threat model).</summary>
	private static string StripControlChars(string value)
	{
		if (value.Length == 0)
		{
			return value;
		}

		StringBuilder sb = new(value.Length);
		foreach (char c in value)
		{
			if (!char.IsControl(c))
			{
				sb.Append(c);
			}
		}

		return sb.ToString();
	}
}
