/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StorageAclEnforcerTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Exercises the runtime ACL path on the real filesystem (Requirement R26). The pure policy in Core
//          decides what "hardened" means; these tests prove the enforcer reads a real DACL, applies the policy
//          and then re-reads it, and - most importantly - that it reports DRIFT when a folder grants the local
//          Users group, which is exactly the state a default ProgramData tree is in.
//          Every test works inside a temporary directory and restores nothing outside it.
// Depends: StorageAclEnforcer, StorageAclPolicy, xUnit
// Extends: Add a scenario here for every new folder the policy covers.

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Security;
using RdpAudit.Service.Security;
using Xunit;

namespace RdpAudit.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class StorageAclEnforcerTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _root;
	private readonly StorageAclEnforcer _enforcer = new(NullLogger<StorageAclEnforcer>.Instance);

	public StorageAclEnforcerTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-acl-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_root);
	}

	public void Dispose()
	{
		try
		{
			if (Directory.Exists(_root))
			{
				Directory.Delete(_root, recursive: true);
			}
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── Applying the policy ──────────────────────────────────────────────────────

	/// <summary>Given a fresh data root, when the policy is applied, then a re-inspection reports every
	/// covered folder compliant - and the covered folders exist, because the apply step creates them.</summary>
	[Fact]
	public void Apply_ThenInspect_ReportsEveryCoveredFolderCompliant()
	{
		StorageAclStatus status = _enforcer.Apply(_root);

		Assert.True(status.Supported);
		Assert.True(status.Compliant, status.Message);
		Assert.All(status.Paths, path => Assert.True(path.Inspected, path.Path + ": " + path.Detail));
		Assert.All(status.Paths, path => Assert.True(path.Compliant, path.Path + ": " + path.Detail));
		foreach (string subfolder in StorageAclPolicy.CoveredSubfolders)
		{
			Assert.True(Directory.Exists(Path.Combine(_root, subfolder)), subfolder + " must exist after the apply pass");
		}
	}

	/// <summary>Given the applied policy, when a folder's DACL is read back directly, then it carries exactly
	/// the two intended grants and no Users grant: the check is not re-reading what it wrote, it is reading the
	/// filesystem.</summary>
	[Fact]
	public void Apply_WritesTheExpectedDescriptorToDisk()
	{
		_enforcer.Apply(_root);

		DirectoryInfo info = new(_root);
		DirectorySecurity security = info.GetAccessControl(AccessControlSections.Access);
		string sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);

		Assert.True(StorageAclPolicy.Assess(sddl).IsCompliant, sddl);
		Assert.True(security.AreAccessRulesProtected, "inheritance must be disabled on the evidence root");
		SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);
		foreach (FileSystemAccessRule rule in security.GetAccessRules(
			includeExplicit: true,
			includeInherited: true,
			targetType: typeof(SecurityIdentifier)))
		{
			Assert.NotEqual(users, (SecurityIdentifier)rule.IdentityReference);
		}
	}

	// ── Detecting drift ──────────────────────────────────────────────────────────

	/// <summary>Given a covered folder that grants the local Users group, when the tree is inspected, then the
	/// drift is reported for THAT folder and the status is not compliant. This is the state a default
	/// ProgramData tree is in, which is what makes the check worth running.</summary>
	[Fact]
	public void Inspect_WhenAFolderGrantsUsers_ReportsDriftAndIsNotCompliant()
	{
		_enforcer.Apply(_root);

		string actions = Path.Combine(_root, "actions");
		DirectoryInfo info = new(actions);
		DirectorySecurity security = info.GetAccessControl();
		security.AddAccessRule(new FileSystemAccessRule(
			new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
			FileSystemRights.ReadAndExecute,
			InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
			PropagationFlags.None,
			AccessControlType.Allow));
		info.SetAccessControl(security);

		StorageAclStatus status = _enforcer.Inspect(_root);

		Assert.True(status.Supported);
		Assert.False(status.Compliant);
		StorageAclPathStatus drifted = Assert.Single(status.Paths, path => !path.Compliant);
		Assert.Equal(actions, drifted.Path);
		Assert.Contains("Users", drifted.Detail, StringComparison.Ordinal);
	}

	// ── Unverifiable is not compliant ────────────────────────────────────────────

	/// <summary>Given a data root that does not exist, when the tree is inspected, then nothing is reported as
	/// compliant: every path is uninspected and the status says so. "We could not look" is never "it is fine".</summary>
	[Fact]
	public void Inspect_OnAMissingTree_IsNotCompliant()
	{
		string missing = Path.Combine(_root, "does-not-exist");

		StorageAclStatus status = _enforcer.Inspect(missing);

		Assert.True(status.Supported);
		Assert.False(status.Compliant);
		Assert.True(status.IsUnverifiable);
		Assert.All(status.Paths, path => Assert.False(path.Inspected));
	}

	/// <summary>Given a blank root, when the enforcer is asked to inspect it, then it refuses the argument
	/// rather than inspecting the current directory.</summary>
	[Fact]
	public void Inspect_WithABlankRoot_Throws()
	{
		Assert.Throws<ArgumentException>(() => _enforcer.Inspect("  "));
	}
}
