// File:    tests/RdpAudit.Core.Tests/AuditPolicyParserTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locale-tolerant decoding of the auditpol /r CSV text. Guards against the previous bug
//          where the Audit tab "Current" column always displayed "?" because the parser expected a
//          numeric bitfield while auditpol actually emits localized text such as "Success and Failure".
//          Also pins the pure CSV parser (D6) used by AuditPolicyManager without spawning auditpol.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Verifies that AuditPolicyManager.DecodeInclusion and ParseAuditpolCsv handle all
/// known auditpol output variants across supported Windows locales, without launching auditpol.</summary>
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

	// ── Pure auditpol CSV parser (D6: no process spawning) ─────────────────────

	[Fact]
	public void ParseAuditpolCsv_EnglishHeader_SuccessAndFailure()
	{
		const string csv =
			"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n"
			+ "HOST,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\r\n";

		AuditPolicyState? state = AuditPolicyManager.ParseAuditpolCsv(csv, AuditPolicyManager.GuidLogon);

		Assert.NotNull(state);
		Assert.True(state!.Success);
		Assert.True(state.Failure);
	}

	[Fact]
	public void ParseAuditpolCsv_EnglishHeader_SuccessOnly()
	{
		const string csv =
			"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n"
			+ "HOST,System,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success,\r\n";

		AuditPolicyState? state = AuditPolicyManager.ParseAuditpolCsv(csv, AuditPolicyManager.GuidSpecialLogon);

		Assert.NotNull(state);
		Assert.True(state!.Success);
		Assert.False(state.Failure);
	}

	[Fact]
	public void ParseAuditpolCsv_RussianHeader_LocalizedInclusion()
	{
		const string csv =
			"Имя компьютера,Целевой объект политики,Подкатегория,GUID подкатегории,Параметр включения,Параметр исключения\r\n"
			+ "HOST,Система,Вход в систему,{0CCE9215-69AE-11D9-BED3-505054503030},Успех и Отказ,\r\n";

		AuditPolicyState? state = AuditPolicyManager.ParseAuditpolCsv(csv, AuditPolicyManager.GuidLogon);

		Assert.NotNull(state);
		Assert.True(state!.Success);
		Assert.True(state.Failure);
	}

	[Fact]
	public void ParseAuditpolCsv_HeaderlessCanonicalLayout_NumericInclusion()
	{
		// Canonical fallback: no recognizable header -> columns 3 (GUID) and 4 (Inclusion).
		const string csv =
			",,,{0CCE9215-69AE-11D9-BED3-505054503030},3,\r\n";

		AuditPolicyState? state = AuditPolicyManager.ParseAuditpolCsv(csv, AuditPolicyManager.GuidLogon);

		Assert.NotNull(state);
		Assert.True(state!.Success);
		Assert.True(state.Failure);
	}

	[Fact]
	public void ParseAuditpolCsv_DifferentGuidRow_ReturnsNull()
	{
		const string csv =
			"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n"
			+ "HOST,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,\r\n";

		Assert.Null(AuditPolicyManager.ParseAuditpolCsv(csv, AuditPolicyManager.GuidLogon));
	}

	[Fact]
	public void ParseAuditpolCsv_EmptyText_Throws()
	{
		Assert.Throws<ArgumentException>(() => AuditPolicyManager.ParseAuditpolCsv(string.Empty, AuditPolicyManager.GuidLogon));
	}

	[Fact]
	public void ParseAuditpolCsv_BlankGuid_Throws()
	{
		Assert.Throws<ArgumentException>(() => AuditPolicyManager.ParseAuditpolCsv("anything", " "));
	}
}
