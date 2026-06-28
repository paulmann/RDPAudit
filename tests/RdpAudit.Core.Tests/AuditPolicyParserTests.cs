// File:    tests/RdpAudit.Core.Tests/AuditPolicyParserTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locale-tolerant decoding of the auditpol /r "Inclusion Setting" column.
//          Guards against the previous bug where the Audit tab "Current" column
//          always displayed "?" because the parser expected a numeric bitfield while
//          auditpol actually emits localized text such as "Success and Failure".
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Verifies that AuditPolicyManager.DecodeInclusion handles all known
/// auditpol /r inclusion-setting text values across supported Windows locales.</summary>
public class AuditPolicyParserTests
{
	[Theory]
	[InlineData("Success and Failure", true, true)]
	[InlineData("Success", true, false)]
	[InlineData("Failure", false, true)]
	[InlineData("No Auditing", false, false)]
	[InlineData("", false, false)]
	[InlineData("3", true, true)]
	[InlineData("1", true, false)]
	[InlineData("2", false, true)]
	[InlineData("0", false, false)]
	[InlineData("Успех и Отказ", true, true)]
	[InlineData("Успех", true, false)]
	[InlineData("Отказ", false, true)]
	[InlineData("Erfolg und Fehler", true, true)]
	[InlineData("Succès et échec", true, true)]
	public void DecodeInclusion_ParsesLocalizedValues(string inclusion, bool success, bool failure)
	{
		AuditPolicyState state = AuditPolicyManager.DecodeInclusion(inclusion);
		Assert.Equal(success, state.Success);
		Assert.Equal(failure, state.Failure);
	}

	[Theory]
	[InlineData("{0CCE9215-69AE-11D9-BED3-505054503030}", "{0CCE9215-69AE-11D9-BED3-505054503030}")]
	[InlineData("0CCE9215-69AE-11D9-BED3-505054503030", "{0CCE9215-69AE-11D9-BED3-505054503030}")]
	[InlineData(" {0cce9215-69ae-11d9-bed3-505054503030} ", "{0CCE9215-69AE-11D9-BED3-505054503030}")]
	public void NormalizeGuid_ProducesStableUppercaseBraceForm(string input, string expected)
	{
		Assert.Equal(expected, AuditPolicyManager.NormalizeGuid(input));
	}
}
