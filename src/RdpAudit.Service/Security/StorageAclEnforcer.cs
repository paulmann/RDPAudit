// File:    src/RdpAudit.Service/Security/StorageAclEnforcer.cs
// Module:  RdpAudit.Service.Security
// Purpose: The runtime half of the storage-ACL requirement: read the DACL of the evidence tree, assess it
//          against StorageAclPolicy, and report drift - optionally repairing it. The decision about what
//          "hardened" means lives in Core as pure SDDL logic; this class only talks to the filesystem.
//          TOLERANCE IS PART OF THE CONTRACT. Organisations legitimately deny ACL changes by policy, run
//          filesystem filter drivers, or place the data root on a share; a service that refused to start
//          because it could not rewrite an ACL would turn a hardening measure into an outage. So every
//          failure to read or write an ACL is reported as "unverifiable" with the reason, and the service
//          carries on. The one thing that never happens is reporting an unreadable ACL as compliant.
// Depends: StorageAclPolicy, RdpAuditPaths
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Security;

/// <summary>One folder's ACL outcome, for the operator report.</summary>
public sealed record StorageAclPathStatus(string Path, bool Inspected, bool Compliant, string Detail);

/// <summary>The whole tree's ACL status.</summary>
public sealed record StorageAclStatus(
	bool Supported,
	bool Compliant,
	IReadOnlyList<StorageAclPathStatus> Paths,
	string Message)
{
	/// <summary>True when nothing could be inspected, so no claim can be made either way.</summary>
	public bool IsUnverifiable => Supported && Paths.All(path => !path.Inspected);
}

/// <summary>Reads, assesses and (when asked) repairs the ACL of the evidence tree.</summary>
public sealed class StorageAclEnforcer
{
	private readonly ILogger<StorageAclEnforcer> _logger;

	/// <summary>Creates the enforcer.</summary>
	public StorageAclEnforcer(ILogger<StorageAclEnforcer> logger)
	{
		ArgumentNullException.ThrowIfNull(logger);
		_logger = logger;
	}

	/// <summary>Inspects the data root and its covered subfolders. Never throws.</summary>
	public StorageAclStatus Inspect(string programDataRoot)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRoot);

		if (!OperatingSystem.IsWindows())
		{
			return new StorageAclStatus(
				Supported: false,
				Compliant: false,
				Paths: [],
				Message: "Filesystem ACL verification is a Windows feature; this host is not Windows.");
		}

		List<StorageAclPathStatus> statuses = [];
		foreach (string path in EnumerateCoveredPaths(programDataRoot))
		{
			statuses.Add(InspectPath(path));
		}

		StorageAclPolicy.StorageAclTreeAssessment tree = new(
			[.. statuses.Select(status => (status.Path, ToAssessment(status)))]);

		return new StorageAclStatus(
			Supported: true,
			Compliant: tree.IsCompliant,
			Paths: statuses,
			Message: tree.Describe());
	}

	/// <summary>
	/// Applies the policy to the data root and every covered subfolder, creating the folders first so a fresh
	/// install ends up hardened rather than merely reported. Returns the post-apply inspection, which is the
	/// only honest way to answer "did it work". Never throws.
	/// </summary>
	[SupportedOSPlatform("windows")]
	public StorageAclStatus Apply(string programDataRoot)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRoot);

		if (!OperatingSystem.IsWindows())
		{
			return Inspect(programDataRoot);
		}

		string root = Path.GetFullPath(programDataRoot);
		List<string> paths = new(EnumerateCoveredPaths(root));
		SecurityIdentifier? writerSid = ResolveWriterSid();

		// Pass 1 - create the whole tree BEFORE any DACL is rewritten. Hardening the root first takes
		// FILE_ADD_SUBDIRECTORY away from the caller: the owner keeps READ_CONTROL and WRITE_DAC (the DACL
		// can still be read and repaired) but loses the right to create a child, and every later
		// Directory.CreateDirectory answers UnauthorizedAccessException. Measured on a non-elevated token:
		// after the root was protected with SYSTEM + Administrators only, creating "...\actions" was
		// refused and the folder never appeared - which produced five "does not exist yet" reports after
		// an otherwise successful apply pass.
		foreach (string path in paths)
		{
			try
			{
				Directory.CreateDirectory(path);
			}
			catch (Exception ex) when (ex is UnauthorizedAccessException or IOException
				or InvalidOperationException or NotSupportedException)
			{
				// Reported, not fatal: the inspection below turns a missing folder into a visible gap and
				// never into a false "compliant".
				_logger.LogWarning(ex, "The storage folder {Path} could not be created", path);
			}
		}

		// Pass 2 - covered subfolders first, the root last. paths[0] is the root by contract of
		// EnumerateCoveredPaths. Hardening the root last means a failure while the tree is being created
		// cannot leave the root protected with its children missing and unreachable.
		for (int index = paths.Count - 1; index >= 1; index--)
		{
			ApplyPolicyTo(paths[index], writerSid);
		}
		ApplyPolicyTo(paths[0], writerSid);

		return Inspect(root);
	}

	/// <summary>
	/// SID of the identity applying the policy, or null when it is SYSTEM or Administrators and therefore
	/// already covered. A filtered administrator token carries BUILTIN\Administrators as deny-only and a
	/// standard user is not a member at all, so a DACL that names only those two locks the applier out of
	/// the very folders it just hardened: Directory.Exists then answers false for an existing folder and
	/// the verdict reads as "the folder does not exist" instead of "compliant".
	/// </summary>
	[SupportedOSPlatform("windows")]
	private static SecurityIdentifier? ResolveWriterSid()
	{
		using WindowsIdentity identity = WindowsIdentity.GetCurrent();
		SecurityIdentifier? writer = identity.User;
		SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
		SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
		return writer is null || writer.Equals(system) || writer.Equals(administrators) ? null : writer;
	}

	/// <summary>Rewrites one folder's DACL to the storage policy. Never throws.</summary>
	[SupportedOSPlatform("windows")]
	private void ApplyPolicyTo(string path, SecurityIdentifier? writerSid)
	{
		try
		{
			DirectoryInfo info = new(path);
			DirectorySecurity security = info.GetAccessControl();

			// Order matters: protect first (which drops the inherited ACEs) and only then add the two
			// explicit grants, so a failure between the steps can never leave the folder with BOTH the
			// inherited Users grant and the intended ones.
			security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
			foreach (FileSystemAccessRule rule in security.GetAccessRules(
				includeExplicit: true,
				includeInherited: false,
				targetType: typeof(SecurityIdentifier)))
			{
				security.RemoveAccessRule(rule);
			}

			security.AddAccessRule(new FileSystemAccessRule(
				new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
				FileSystemRights.FullControl,
				InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
				PropagationFlags.None,
				AccessControlType.Allow));
			security.AddAccessRule(new FileSystemAccessRule(
				new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
				FileSystemRights.FullControl,
				InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
				PropagationFlags.None,
				AccessControlType.Allow));

			// ReadAndExecute keeps the applier able to verify the result it just produced; it is not granted
			// in production, where the applier is LocalSystem or an elevated administrator and is skipped.
			if (writerSid is not null)
			{
				security.AddAccessRule(new FileSystemAccessRule(
					writerSid,
					FileSystemRights.ReadAndExecute,
					InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
					PropagationFlags.None,
					AccessControlType.Allow));
			}

			info.SetAccessControl(security);
			_logger.LogInformation("Storage ACL applied to {Path}", path);
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException or PrivilegeNotHeldException
			or IOException or InvalidOperationException or PlatformNotSupportedException)
		{
			// Denied by policy, filtered by a security product, or unsupported: report and continue. A
			// hardening measure that stops the service is a worse outcome than a reported gap.
			_logger.LogWarning(ex, "The storage ACL for {Path} could not be applied", path);
		}
	}

	/// <summary>Reads one folder's DACL and assesses it.</summary>
	[SupportedOSPlatform("windows")]
	private StorageAclPathStatus InspectPath(string path)
	{
		try
		{
			if (!DirectoryExists(path))
			{
				return new StorageAclPathStatus(
					path,
					Inspected: false,
					Compliant: false,
					Detail: "The folder does not exist yet, so its ACL cannot be verified. It inherits the "
						+ "policy when it is created by a process that applies it.");
			}

			DirectoryInfo info = new(path);
			DirectorySecurity security = info.GetAccessControl(AccessControlSections.Access);
			string sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
			StorageAclAssessment assessment = StorageAclPolicy.Assess(sddl);
			return new StorageAclPathStatus(path, assessment.IsVerifiable, assessment.IsCompliant, assessment.Describe());
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException
			or PlatformNotSupportedException or SystemException)
		{
			// Unverifiable, never compliant - see the file header.
			return new StorageAclPathStatus(
				path,
				Inspected: false,
				Compliant: false,
				Detail: string.Create(
					CultureInfo.InvariantCulture,
					$"The ACL could not be read ({ex.GetType().Name}: {ex.Message}), so compliance cannot be established."));
		}
	}

	/// <summary>
	/// True only when the path is genuinely absent. <see cref="Directory.Exists(string)"/> answers false for
	/// an existing folder the caller may not open, which would report a hardened folder as missing - the
	/// opposite of an audit gap. Reading the attributes throws DirectoryNotFoundException for a missing path
	/// and UnauthorizedAccessException for a denied one, so the two cases stay distinguishable and the caller
	/// reports the denied one as unverifiable.
	/// </summary>
	private static bool DirectoryExists(string path)
	{
		try
		{
			_ = new DirectoryInfo(path).Attributes;
			return true;
		}
		catch (DirectoryNotFoundException)
		{
			return false;
		}
		catch (FileNotFoundException)
		{
			return false;
		}
	}

	private static StorageAclAssessment ToAssessment(StorageAclPathStatus status)
		=> status.Inspected
			? status.Compliant ? StorageAclAssessment.Compliant() : new StorageAclAssessment(true, false, [status.Detail])
			: StorageAclAssessment.Unverifiable(status.Detail);

	/// <summary>The data root plus every covered subfolder, as absolute paths.</summary>
	private static IEnumerable<string> EnumerateCoveredPaths(string programDataRoot)
	{
		string root = Path.GetFullPath(programDataRoot);
		yield return root;
		foreach (string subfolder in StorageAclPolicy.CoveredSubfolders)
		{
			yield return Path.Combine(root, subfolder);
		}
	}
}
