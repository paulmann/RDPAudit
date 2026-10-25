/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StorageAclPolicy.cs
// Project: RdpAudit.Core (RdpAudit.Core.Security)
// Purpose: The expected discretionary ACL of the evidence tree, and the check that a real ACL matches it.
//          It is pure text - SDDL in, findings out - for two reasons: the rule is then reviewable without a
//          filesystem, and the same check serves install.ps1 (which asserts the ACL), the service (which
//          verifies it at start-up) and the tests, so the three cannot disagree about what "hardened" means.
//          The policy itself: SYSTEM and BUILTIN\Administrators have full control, inheritance from the
//          parent is DISABLED (so a permissive ProgramData default cannot leak back in), and no ACE grants
//          anything to Users, Authenticated Users or Everyone - the evidence store holds every source address,
//          every account and every RDP session of the host, and the local Users group has no business reading
//          it.
//          Honest limits, stated because a security check that overstates itself is worse than none:
//            - the check is TEXTUAL over the DACL segment. It does not resolve group membership, so an
//              administrator who added a nested group to Administrators is not detected - and does not need
//              to be, because that is what Administrators means.
//            - an ACL that cannot be read (access denied, non-Windows, missing folder) is reported as
//              UNVERIFIABLE, never as compliant. "We could not look" is not "we looked and it was fine".
// Depends: none
// Extends: Add a finding to Assess whenever the policy changes, and mirror the change in install.ps1's
//          Set-RdpAuditFolderAcl, which asserts the same descriptor.

using System.Globalization;

namespace RdpAudit.Core.Security;

/// <summary>Outcome of assessing one ACL against the expected storage policy.</summary>
public sealed record StorageAclAssessment(
	bool IsVerifiable,
	bool IsCompliant,
	IReadOnlyList<string> Findings)
{
	/// <summary>Human-readable summary of the assessment.</summary>
	public string Describe()
		=> !IsVerifiable
			? Findings.Count > 0 ? string.Join("; ", Findings) : "The ACL could not be read."
			: IsCompliant ? "The ACL matches the storage policy." : string.Join("; ", Findings);

	/// <summary>An assessment whose ACL could not be read. Never compliant - see the file header.</summary>
	public static StorageAclAssessment Unverifiable(string reason)
		=> new(false, false, [reason]);

	/// <summary>An assessment of a compliant ACL.</summary>
	public static StorageAclAssessment Compliant() => new(true, true, []);
}

/// <summary>The expected DACL of <c>%ProgramData%\RdpAudit</c> and its subfolders, as SDDL text plus the
/// check that a real ACL satisfies it.</summary>
public static class StorageAclPolicy
{
	/// <summary>SDDL of the DACL the product asserts: protected (inheritance disabled), SYSTEM and
	/// Administrators full control, inherited by containers and objects so every file written later carries
	/// the same rules without a per-file pass.</summary>
	public const string ExpectedDaclSddl = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

	/// <summary>Well-known SIDs that must never appear in a grant on the evidence tree: Users, Everyone and
	/// Authenticated Users.</summary>
	public static readonly string[] ForbiddenGrantSids = ["BU", "WD", "AU"];

	/// <summary>Subfolders of the data root the policy covers, so the check and the installer walk the same
	/// set. Root-relative names; the database and its sidecars live directly in the root.</summary>
	public static readonly string[] CoveredSubfolders = ["actions", "Backups", "logs", "crash", "integrity"];

	/// <summary>Human-readable description of the policy, for the installer output and the database tab.</summary>
	public static string DescribeExpected()
		=> "SYSTEM and Administrators have FullControl; inheritance from the parent folder is disabled; no "
			+ "access is granted to Users, Authenticated Users or Everyone.";

	/// <summary>
	/// Assesses a security descriptor in SDDL form. An empty value is unverifiable; a value with no DACL
	/// segment is unverifiable; anything else is checked against the policy.
	/// </summary>
	public static StorageAclAssessment Assess(string? sddl)
	{
		if (string.IsNullOrWhiteSpace(sddl))
		{
			return StorageAclAssessment.Unverifiable(
				"The security descriptor could not be read, so ACL compliance cannot be established.");
		}

		int daclIndex = FindDaclSegment(sddl);
		if (daclIndex < 0)
		{
			return StorageAclAssessment.Unverifiable(
				"The security descriptor carries no DACL segment (no 'D:' component), so there is nothing to "
					+ "check against the storage policy. An absent DACL grants everyone full control.");
		}

		string dacl = sddl[daclIndex..];
		List<string> findings = [];

		// The DACL value is a flags letter group followed by the ACE list, e.g. "PAI(A;OICI;FA;;;SY)...".
		// 'P' is what makes the DACL protected: without it the parent's ACEs are still inherited, and
		// %ProgramData% inherits a Users read grant by default - the exact leak this policy removes.
		int firstAce = dacl.IndexOf('(', StringComparison.Ordinal);
		string daclFlags = firstAce < 0 ? dacl : dacl[..firstAce];
		bool isProtected = daclFlags.Contains('P');
		if (!isProtected)
		{
			findings.Add(
				"The DACL is not protected: inheritance from the parent folder is still enabled, so "
					+ "permissive root ACEs (typically a Users read grant on ProgramData) are inherited into "
					+ "the evidence tree.");
		}

		foreach (string forbidden in ForbiddenGrantSids)
		{
			if (HasGrantAce(dacl, forbidden))
			{
				findings.Add(
					"An allow ACE grants access to " + DescribeSid(forbidden) + ", which the storage policy "
						+ "forbids: the store holds every source address, account and session of this host.");
			}
		}

		if (!HasGrantAce(dacl, "SY"))
		{
			findings.Add(
				"No allow ACE grants FullControl to SYSTEM. The service runs as LocalSystem and writes the "
					+ "database, its WAL and the shard tree; without this ACE it cannot.");
		}

		if (!HasGrantAce(dacl, "BA"))
		{
			findings.Add(
				"No allow ACE grants FullControl to BUILTIN\\Administrators. An administrator must be able to "
					+ "recover the evidence store; removing that is not hardening, it is lock-out.");
		}

		if (!HasInheritanceFlags(dacl, "SY") || !HasInheritanceFlags(dacl, "BA"))
		{
			findings.Add(
				"The SYSTEM and Administrators ACEs do not carry both ObjectInherit and ContainerInherit, so "
					+ "files created later in the tree would not inherit them.");
		}

		return findings.Count == 0
			? StorageAclAssessment.Compliant()
			: new StorageAclAssessment(true, false, findings);
	}

	/// <summary>True when the DACL holds an allow ACE for the given well-known SID (or one of its aliases).</summary>
	private static bool HasGrantAce(string dacl, string sid)
	{
		foreach (string ace in EnumerateAces(dacl))
		{
			if (!IsAllowAce(ace))
			{
				continue;
			}

			if (string.Equals(SidOf(ace), sid, StringComparison.Ordinal))
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>True when the allow ACE for <paramref name="sid"/> carries both inheritance flags.</summary>
	private static bool HasInheritanceFlags(string dacl, string sid)
	{
		foreach (string ace in EnumerateAces(dacl))
		{
			if (!IsAllowAce(ace) || !string.Equals(SidOf(ace), sid, StringComparison.Ordinal))
			{
				continue;
			}

			string flags = FlagsOf(ace);
			return flags.Contains("OI", StringComparison.Ordinal) && flags.Contains("CI", StringComparison.Ordinal);
		}

		return false;
	}

	/// <summary>Enumerates the ACEs of a DACL segment, ignoring the flags between 'D:' and the first '('.</summary>
	private static IEnumerable<string> EnumerateAces(string daclSegment)
	{
		int index = daclSegment.IndexOf('(', StringComparison.Ordinal);
		while (index >= 0 && index < daclSegment.Length)
		{
			int end = daclSegment.IndexOf(')', index);
			if (end < 0)
			{
				yield break;
			}

			yield return daclSegment[(index + 1)..end];
			index = daclSegment.IndexOf('(', end);
		}
	}

	/// <summary>An ACE string starts with its AceType: 'A' for allow, 'D' for deny.</summary>
	private static bool IsAllowAce(string ace) => ace.Length > 0 && ace[0] == 'A';

	/// <summary>ACE layout: <c>type;flags;rights;objectGuid;inheritObjectGuid;sid</c>.</summary>
	private static string SidOf(string ace)
	{
		string[] parts = ace.Split(';');
		return parts.Length >= 6 ? parts[5] : string.Empty;
	}

	private static string FlagsOf(string ace)
	{
		string[] parts = ace.Split(';');
		return parts.Length >= 2 ? parts[1] : string.Empty;
	}

	/// <summary>
	/// Index of the value that follows the <c>D:</c> component, or -1. SDDL is a sequence of
	/// <c>&lt;letter&gt;:&lt;value&gt;</c> components (owner, group, DACL, SACL) and a SID value never
	/// contains a colon, so the colons are unambiguous component separators; the prefix letter of the next
	/// component is the last character of the current value. That is what makes this a parse rather than a
	/// search for the two characters "D:" - which would also match a SID inside a group value.
	/// </summary>
	internal static int FindDaclSegment(string sddl)
	{
		string[] parts = sddl.Split(':');
		if (parts.Length < 2 || parts[0].Length == 0)
		{
			return -1;
		}

		char prefix = parts[0][0];
		int offset = 0;
		for (int index = 1; index < parts.Length; index++)
		{
			bool isLast = index == parts.Length - 1;
			string value = isLast ? parts[index] : parts[index][..^1];
			if (prefix is 'D' or 'S')
			{
				return prefix == 'D' ? offset : -1;
			}

			// Advance past "<prefix>:<value><nextPrefix>".
			offset += 2 + value.Length;
			prefix = isLast ? '\0' : parts[index][^1];
		}

		return -1;
	}

	private static string DescribeSid(string sid) => sid switch
	{
		"BU" => "BUILTIN\\Users",
		"WD" => "Everyone",
		"AU" => "NT AUTHORITY\\Authenticated Users",
		_ => sid,
	};

	/// <summary>The per-path assessment of a whole tree.</summary>
	public sealed record StorageAclTreeAssessment(IReadOnlyList<(string Path, StorageAclAssessment Assessment)> Paths)
	{
		/// <summary>True when every inspected path is compliant. An empty list is NOT compliant: nothing was
		/// inspected, so nothing is proven.</summary>
		public bool IsCompliant => Paths.Count > 0 && Paths.All(entry => entry.Assessment.IsCompliant);

		/// <summary>Number of paths that could not be read at all.</summary>
		public int UnverifiableCount => Paths.Count(entry => !entry.Assessment.IsVerifiable);

		/// <summary>Human-readable summary naming every path that is not compliant.</summary>
		public string Describe()
		{
			if (Paths.Count == 0)
			{
				return "No folder was inspected, so ACL compliance cannot be established.";
			}

			if (IsCompliant)
			{
				return string.Create(
					CultureInfo.InvariantCulture,
					$"All {Paths.Count} evidence-tree folder(s) match the storage policy.");
			}

			List<string> offenders = [];
			foreach ((string path, StorageAclAssessment assessment) in Paths)
			{
				if (!assessment.IsCompliant)
				{
					offenders.Add(path + ": " + assessment.Describe());
				}
			}

			return string.Join(" | ", offenders);
		}
	}
}
