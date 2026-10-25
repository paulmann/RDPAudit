/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StorageAclAndEncryptionTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: Pins the two storage-hardening decisions that are enforced in code rather than by an operator:
//          the storage ACL policy (SYSTEM + Administrators, inheritance disabled, no Users) and the
//          encryption-at-rest guard (fail closed on a mode this build cannot honour).
//          Both are asserted from the compliant side AND from the non-compliant side: a verifier that
//          accepts everything and a guard that refuses everything are equally useless, so every acceptance
//          case is paired with the rejection it must produce.
// Depends: StorageAclPolicy, StorageEncryptionGuard, xUnit
// Extends: Add a case here whenever the policy or the guard gains a rule.

using RdpAudit.Core.Config;
using RdpAudit.Core.Security;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class StorageAclAndEncryptionTests
{
	// ── Storage ACL policy ───────────────────────────────────────────────────────

	/// <summary>The descriptor the product asserts is accepted, together with the installer's SDDL form
	/// carrying the owner and group components in front of the DACL.</summary>
	[Theory]
	[InlineData(StorageAclPolicy.ExpectedDaclSddl)]
	[InlineData("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")]
	[InlineData("O:S-1-5-18G:S-1-5-32-544D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")]
	public void Assess_OnTheExpectedDescriptor_IsCompliant(string sddl)
	{
		StorageAclAssessment assessment = StorageAclPolicy.Assess(sddl);

		Assert.True(assessment.IsVerifiable);
		Assert.True(assessment.IsCompliant, assessment.Describe());
		Assert.Empty(assessment.Findings);
	}

	/// <summary>An ACL that grants the local Users group is not compliant: the evidence store holds every
	/// source address, account and session of the host.</summary>
	[Fact]
	public void Assess_WhenUsersAreGranted_IsNotCompliant()
	{
		StorageAclAssessment assessment = StorageAclPolicy.Assess(
			"O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)");

		Assert.True(assessment.IsVerifiable);
		Assert.False(assessment.IsCompliant);
		Assert.Contains(assessment.Findings, finding => finding.Contains("BUILTIN\\Users", StringComparison.Ordinal));
	}

	/// <summary>An ACL whose inheritance is still enabled is not compliant even when the explicit ACEs look
	/// right: the ProgramData default (Users: read) is inherited back in.</summary>
	[Fact]
	public void Assess_WhenInheritanceIsNotDisabled_IsNotCompliant()
	{
		StorageAclAssessment assessment = StorageAclPolicy.Assess("O:BAG:SYD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");

		Assert.False(assessment.IsCompliant);
		Assert.Contains(assessment.Findings, finding => finding.Contains("not protected", StringComparison.Ordinal));
	}

	/// <summary>An ACL missing one of the two required grants is not compliant: SYSTEM cannot lose access
	/// (the service writes the store) and Administrators cannot either (that would be lock-out, not
	/// hardening).</summary>
	[Theory]
	[InlineData("D:PAI(A;OICI;FA;;;BA)", "SYSTEM")]
	[InlineData("D:PAI(A;OICI;FA;;;SY)", "BUILTIN\\Administrators")]
	public void Assess_WhenARequiredGrantIsMissing_IsNotCompliant(string sddl, string expectedFinding)
	{
		StorageAclAssessment assessment = StorageAclPolicy.Assess(sddl);

		Assert.False(assessment.IsCompliant);
		Assert.Contains(assessment.Findings, finding => finding.Contains(expectedFinding, StringComparison.Ordinal));
	}

	/// <summary>An ACL without the inheritance flags would not cover files created later, so it is not
	/// compliant.</summary>
	[Fact]
	public void Assess_WhenTheGrantsDoNotInherit_IsNotCompliant()
	{
		StorageAclAssessment assessment = StorageAclPolicy.Assess("D:PAI(A;;FA;;;SY)(A;;FA;;;BA)");

		Assert.False(assessment.IsCompliant);
		Assert.Contains(assessment.Findings, finding => finding.Contains("ObjectInherit", StringComparison.Ordinal));
	}

	/// <summary>An ACL that cannot be read - or that carries no DACL at all - is UNVERIFIABLE, never
	/// compliant: "we could not look" must not read as "we looked and it was fine".</summary>
	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("O:BAG:SY")]
	public void Assess_WhenThereIsNothingToCheck_IsUnverifiableAndNotCompliant(string? sddl)
	{
		StorageAclAssessment assessment = StorageAclPolicy.Assess(sddl);

		Assert.False(assessment.IsVerifiable);
		Assert.False(assessment.IsCompliant);
		Assert.NotEmpty(assessment.Findings);
	}

	/// <summary>A tree with no inspected path is not compliant: nothing was inspected, so nothing is
	/// proven.</summary>
	[Fact]
	public void TreeAssessment_WithNoInspectedPath_IsNotCompliant()
	{
		StorageAclPolicy.StorageAclTreeAssessment tree = new([]);

		Assert.False(tree.IsCompliant);
		Assert.Contains("cannot be established", tree.Describe(), StringComparison.Ordinal);
	}

	/// <summary>The policy name is described in operator terms, so the Database tab and the installer can
	/// state what "hardened" means without inventing their own wording.</summary>
	[Fact]
	public void DescribeExpected_NamesTheThreeRules()
	{
		string description = StorageAclPolicy.DescribeExpected();

		Assert.Contains("SYSTEM", description, StringComparison.Ordinal);
		Assert.Contains("Administrators", description, StringComparison.Ordinal);
		Assert.Contains("inheritance", description, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("Users", description, StringComparison.Ordinal);
	}

	// ── Encryption at rest ───────────────────────────────────────────────────────

	/// <summary>The default mode is None, and it needs no comment: the store is plain text, which is exactly
	/// what the setting says.</summary>
	[Fact]
	public void Guard_OnTheDefaultMode_IsSilent()
	{
		StorageEncryptionOptions options = new();

		Assert.Equal(StorageEncryptionMode.None, options.Mode);
		Assert.True(options.IsEffectivelyUnencrypted);
		Assert.Null(StorageEncryptionGuard.AssertSupported(options));
		Assert.Null(StorageEncryptionGuard.AssertSupported(null));
	}

	/// <summary>Selecting SQLCipher, which this build does not implement, refuses to start with an actionable
	/// message: the alternative is a service running with plain-text files under a setting that claims
	/// encryption.</summary>
	[Fact]
	public void Guard_OnSqlCipher_RefusesToStart()
	{
		StorageEncryptionOptions options = new() { Mode = StorageEncryptionMode.SqlCipher };

		StorageEncryptionNotSupportedException exception = Assert.Throws<StorageEncryptionNotSupportedException>(
			() => StorageEncryptionGuard.AssertSupported(options));

		Assert.Equal(StorageEncryptionMode.SqlCipher, exception.Mode);
		Assert.Contains("not implemented in this build", exception.Message, StringComparison.Ordinal);
		Assert.Contains("docs/89-encryption-at-rest-decision.md", exception.Message, StringComparison.Ordinal);
		Assert.False(options.IsEffectivelyUnencrypted);
	}

	/// <summary>An out-of-range numeric override is refused rather than treated as None, so a hand-edited
	/// settings file cannot silently disable encryption by writing a value the enum does not define.</summary>
	[Fact]
	public void Guard_OnAnUnknownValue_RefusesToStart()
	{
		StorageEncryptionOptions options = new() { Mode = (StorageEncryptionMode)99 };

		Assert.Throws<StorageEncryptionNotSupportedException>(() => StorageEncryptionGuard.AssertSupported(options));
	}

	/// <summary>VolumeManaged is honoured - the volume does the work - but the product cannot verify the
	/// volume's state, so it warns in exactly those terms instead of confirming an encryption it cannot see.</summary>
	[Fact]
	public void Guard_OnVolumeManaged_WarnsThatItCannotVerifyTheVolume()
	{
		StorageEncryptionOptions options = new() { Mode = StorageEncryptionMode.VolumeManaged };

		string? warning = StorageEncryptionGuard.AssertSupported(options);

		Assert.NotNull(warning);
		Assert.Contains("cannot verify the volume's state", warning, StringComparison.Ordinal);
		Assert.Contains("docs/89-encryption-at-rest-decision.md", warning, StringComparison.Ordinal);
	}

	/// <summary>The described options never carry key material: only the NAME of the secret and the rotation
	/// interval appear, so this string is safe to log.</summary>
	[Fact]
	public void Describe_ReportsOnlyTheSecretNameAndNeverKeyMaterial()
	{
		StorageEncryptionOptions options = new()
		{
			Mode = StorageEncryptionMode.VolumeManaged,
			KeySecretName = "RdpAudit:DbKey",
			KeyRotationDays = 90,
		};

		string description = options.Describe();

		Assert.Contains("KeyConfigured=True", description, StringComparison.Ordinal);
		Assert.Contains("KeyRotationDays=90", description, StringComparison.Ordinal);
		Assert.DoesNotContain("secret value", description, StringComparison.OrdinalIgnoreCase);
	}
}
