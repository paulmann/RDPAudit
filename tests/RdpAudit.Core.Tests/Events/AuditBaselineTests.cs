// File:    tests/RdpAudit.Core.Tests/Events/AuditBaselineTests.cs
// Module:  RdpAudit.Core.Tests.Events
// Purpose: Pins the D6 security-audit baseline: five subcategories (Logon, Special Logon,
//          Account Lockout, Credential Validation, Kerberos Authentication Service) each
//          required with Success AND Failure, the locale-stable subcategory GUIDs, and the
//          pure evaluation fold used by the Configurator's aggregated prerequisite probe.
//          Deliberately spawns no processes: EvaluateBaseline is a pure function, so these
//          tests are deterministic and safe to run anywhere (including CI).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

/// <summary>Verifies the D6 audit-policy baseline contract without touching the host policy.</summary>
public sealed class AuditBaselineTests
{
	[Fact]
	public void BaselineRows_FiveDistinctSubcategories_AllRequireSuccessAndFailure()
	{
		IReadOnlyList<AuditPolicyRow> rows = AuditPolicyManager.BaselineRows;

		Assert.Equal(5, rows.Count);
		Assert.Equal(5, rows.Select(r => r.SubcategoryGuid).Distinct(StringComparer.OrdinalIgnoreCase).Count());
		Assert.All(rows, r =>
		{
			Assert.True(r.Success, r.Subcategory + " must require Success auditing");
			Assert.True(r.Failure, r.Subcategory + " must require Failure auditing");
			Assert.True(Guid.TryParse(r.SubcategoryGuid.Trim('{', '}'), out _),
				r.Subcategory + " GUID is invalid: " + r.SubcategoryGuid);
		});
	}

	[Fact]
	public void BaselineRows_PinStableLocaleInvariantGuids()
	{
		Dictionary<string, string> byName = AuditPolicyManager.BaselineRows
			.ToDictionary(r => r.Subcategory, r => r.SubcategoryGuid, StringComparer.Ordinal);

		// 4624/4625
		Assert.Equal("{0CCE9215-69AE-11D9-BED3-505054503030}", byName["Logon"]);
		// 4672
		Assert.Equal("{0CCE921B-69AE-11D9-BED3-505054503030}", byName["Special Logon"]);
		// 4740
		Assert.Equal("{0CCE9217-69AE-11D9-BED3-505054503030}", byName["Account Lockout"]);
		// 4776
		Assert.Equal("{0CCE923F-69AE-11D9-BED3-505054503030}", byName["Credential Validation"]);
		// 4768
		Assert.Equal("{0CCE9242-69AE-11D9-BED3-505054503030}", byName["Kerberos Authentication Service"]);
	}

	[Fact]
	public void EvaluateBaseline_AllSuccessAndFailure_AllOk()
	{
		Dictionary<string, AuditPolicyState?> current = BuildStates(success: true, failure: true);

		IReadOnlyList<AuditBaselineResult> verdicts = AuditPolicyManager.EvaluateBaseline(current);

		Assert.Equal(5, verdicts.Count);
		Assert.All(verdicts, v =>
		{
			Assert.True(v.Ok, v.Subcategory + " must pass");
			Assert.NotNull(v.Current);
			Assert.True(v.Current!.Success);
			Assert.True(v.Current.Failure);
		});
	}

	[Fact]
	public void EvaluateBaseline_SuccessOnlySpecialLogon_NotOk()
	{
		Dictionary<string, AuditPolicyState?> current = BuildStates(success: true, failure: true);
		current[AuditPolicyManager.GuidSpecialLogon] = new AuditPolicyState(true, false);

		AuditBaselineResult special = AuditPolicyManager.EvaluateBaseline(current)
			.Single(v => v.SubcategoryGuid == AuditPolicyManager.GuidSpecialLogon);

		Assert.False(special.Ok);
		Assert.False(special.Current!.Failure);
	}

	[Fact]
	public void EvaluateBaseline_UnreadableSubcategory_NullCurrentAndNotOk()
	{
		Dictionary<string, AuditPolicyState?> current = BuildStates(success: true, failure: true);
		current[AuditPolicyManager.GuidCredentialValidation] = null;

		AuditBaselineResult credential = AuditPolicyManager.EvaluateBaseline(current)
			.Single(v => v.SubcategoryGuid == AuditPolicyManager.GuidCredentialValidation);

		Assert.False(credential.Ok);
		Assert.Null(credential.Current);
	}

	[Fact]
	public void EvaluateBaseline_ResolvesCaseInsensitiveGuidKeys()
	{
		Dictionary<string, AuditPolicyState?> current = new(StringComparer.OrdinalIgnoreCase);
		foreach (AuditPolicyRow row in AuditPolicyManager.BaselineRows)
		{
			current[row.SubcategoryGuid.ToLowerInvariant()] = new AuditPolicyState(true, true);
		}

		Assert.All(AuditPolicyManager.EvaluateBaseline(current), v => Assert.True(v.Ok));
	}

	[Fact]
	public void EvaluateBaseline_NullDictionary_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => AuditPolicyManager.EvaluateBaseline(null!));
	}

	private static Dictionary<string, AuditPolicyState?> BuildStates(bool success, bool failure)
	{
		Dictionary<string, AuditPolicyState?> map = new(StringComparer.OrdinalIgnoreCase);
		foreach (AuditPolicyRow row in AuditPolicyManager.BaselineRows)
		{
			map[row.SubcategoryGuid] = new AuditPolicyState(success, failure);
		}

		return map;
	}
}
