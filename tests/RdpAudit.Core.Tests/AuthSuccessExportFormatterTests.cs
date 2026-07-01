// File:    tests/RdpAudit.Core.Tests/AuthSuccessExportFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the AuthSuccessExportFormatter contract across JSON / TXT / Markdown / CSV. The
//          report is a PER-LOGIN roll-up (one row per account, never one row per attempt): every
//          format must carry the login name, successful / failed / denied counts, the number of
//          failed authentications before the first success, the time-to-first-success, the attacker
//          IP, and the decoded success-event evidence (e.g. 4624 → successful logon). Also locks the
//          file-naming and event-meaning helpers.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Coverage for the "Export Auth Success (per login)" formatter.</summary>
public class AuthSuccessExportFormatterTests
{
	// ── Sample data ──────────────────────────────────────────────────────────────

	/// <summary>Builds a DTO with two logins: "administrator" whose password was guessed after
	/// 168 failed attempts (attacker success), and "svc_backup" that never succeeded.</summary>
	private static AuthSuccessSummaryDto SampleDto() => new()
	{
		Status = IpcResultStatus.Success,
		Ip = "45.227.254.38",
		QueriedUtc = new DateTime(2026, 6, 20, 10, 0, 0, DateTimeKind.Utc),
		TotalAuthFacts = 59577,
		TotalSuccessfulAuth = 23905,
		TotalFailedAuth = 35672,
		TotalDeniedAuth = 0,
		DistinctSucceededLogins = 1,
		DistinctLoginsObserved = 2,
		FirstSeenUtc = new DateTime(2026, 6, 18, 8, 0, 0, DateTimeKind.Utc),
		LastSeenUtc = new DateTime(2026, 6, 20, 9, 40, 0, DateTimeKind.Utc),
		SucceededLoginsOnly = true,
		Logins = new List<AuthSuccessLoginDto>
		{
			new()
			{
				NormalizedUserName = "administrator",
				DisplayUserName = "Administrator",
				Domain = "CORP",
				SuccessfulAuthCount = 23905,
				FailedAuthCount = 168,
				DeniedAuthCount = 0,
				TotalAuthCount = 24073,
				FailedBeforeFirstSuccess = 168,
				FirstSeenUtc = new DateTime(2026, 6, 18, 8, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 6, 20, 9, 40, 0, DateTimeKind.Utc),
				FirstSuccessUtc = new DateTime(2026, 6, 18, 10, 5, 0, DateTimeKind.Utc),
				LastSuccessUtc = new DateTime(2026, 6, 20, 9, 40, 0, DateTimeKind.Utc),
				SecondsToFirstSuccess = 7500,
				SuccessEventIds = new List<int> { 4624 },
				SuccessLogonTypes = new List<int> { 3 },
				SuccessAuthPackages = new List<string> { "NTLM" },
				FailureReasons = new List<string> { "0xC000006A" },
				HasSuccess = true,
			},
			new()
			{
				NormalizedUserName = "svc_backup",
				DisplayUserName = "svc_backup",
				Domain = null,
				SuccessfulAuthCount = 0,
				FailedAuthCount = 5000,
				DeniedAuthCount = 12,
				TotalAuthCount = 5012,
				FailedBeforeFirstSuccess = 5012,
				FirstSeenUtc = new DateTime(2026, 6, 19, 1, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 6, 20, 2, 0, 0, DateTimeKind.Utc),
				FirstSuccessUtc = null,
				LastSuccessUtc = null,
				SecondsToFirstSuccess = null,
				SuccessEventIds = new List<int>(),
				SuccessLogonTypes = new List<int>(),
				SuccessAuthPackages = new List<string>(),
				FailureReasons = new List<string> { "0xC0000064" },
				HasSuccess = false,
			},
		},
	};

	// ── JSON ─────────────────────────────────────────────────────────────────────

	[Fact]
	public void FormatJson_IsParseableAndCarriesPerLoginRollup()
	{
		string json = AuthSuccessExportFormatter.Format(SampleDto(), AuthSuccessExportFormat.Json);

		using JsonDocument doc = JsonDocument.Parse(json);
		JsonElement root = doc.RootElement;

		Assert.Equal("45.227.254.38", root.GetProperty("ip").GetString());
		Assert.True(root.GetProperty("succeededLoginsOnly").GetBoolean());

		JsonElement totals = root.GetProperty("ipTotals");
		Assert.Equal(59577, totals.GetProperty("totalAuthFacts").GetInt64());
		Assert.Equal(23905, totals.GetProperty("totalSuccessfulAuth").GetInt64());

		JsonElement logins = root.GetProperty("logins");
		Assert.Equal(2, logins.GetArrayLength());

		JsonElement admin = logins[0];
		Assert.Equal("administrator", admin.GetProperty("normalizedUserName").GetString());
		Assert.Equal("45.227.254.38", admin.GetProperty("attackerIp").GetString());
		Assert.True(admin.GetProperty("hasSuccess").GetBoolean());
		Assert.Equal(168, admin.GetProperty("failedBeforeFirstSuccess").GetInt64());
		Assert.Equal(7500, admin.GetProperty("secondsToFirstSuccess").GetInt64());

		// Decision evidence must decode event 4624 → successful logon.
		JsonElement evidence = admin.GetProperty("successEvidence");
		Assert.Equal(1, evidence.GetArrayLength());
		Assert.Equal(4624, evidence[0].GetProperty("eventId").GetInt32());
		Assert.Contains("successful logon", evidence[0].GetProperty("meaning").GetString(), StringComparison.OrdinalIgnoreCase);
	}

	// ── TXT ──────────────────────────────────────────────────────────────────────

	[Fact]
	public void FormatTxt_ContainsLoginCountsEvidenceAndAttackerIp()
	{
		string txt = AuthSuccessExportFormatter.Format(SampleDto(), AuthSuccessExportFormat.Txt);

		Assert.Contains("Attacker IP: 45.227.254.38", txt, StringComparison.Ordinal);
		Assert.Contains("administrator", txt, StringComparison.Ordinal);
		Assert.Contains("Password guessed?     : YES", txt, StringComparison.Ordinal);
		Assert.Contains("Failed before success : 168", txt, StringComparison.Ordinal);
		Assert.Contains("Successful auth       : 23905", txt, StringComparison.Ordinal);
		// Event 4624 must be decoded into a human-readable meaning.
		Assert.Contains("4624", txt, StringComparison.Ordinal);
		Assert.Contains("successful logon", txt, StringComparison.OrdinalIgnoreCase);
		// The never-succeeded login is still present but marked "no" (succeeded-only scope is a server concern).
		Assert.Contains("svc_backup", txt, StringComparison.Ordinal);
	}

	[Fact]
	public void FormatTxt_NoLogins_RendersEmptyNotice()
	{
		AuthSuccessSummaryDto dto = SampleDto();
		dto.Logins = new List<AuthSuccessLoginDto>();

		string txt = AuthSuccessExportFormatter.Format(dto, AuthSuccessExportFormat.Txt);

		Assert.Contains("no matching logins for this IP", txt, StringComparison.OrdinalIgnoreCase);
	}

	// ── Markdown ───────────────────────────────────────────────────────────────────

	[Fact]
	public void FormatMarkdown_HasTableHeaderAndPerLoginRows()
	{
		string md = AuthSuccessExportFormatter.Format(SampleDto(), AuthSuccessExportFormat.Markdown);

		Assert.Contains("# RdpAudit — Auth Success per-login export", md, StringComparison.Ordinal);
		Assert.Contains("| # | Login | Domain | Guessed? |", md, StringComparison.Ordinal);
		Assert.Contains("administrator", md, StringComparison.Ordinal);
		Assert.Contains("| YES |", md, StringComparison.Ordinal);
		Assert.Contains("svc_backup", md, StringComparison.Ordinal);
	}

	// ── CSV ──────────────────────────────────────────────────────────────────────

	[Fact]
	public void FormatCsv_HeaderPlusOneRowPerLogin()
	{
		string csv = AuthSuccessExportFormatter.Format(SampleDto(), AuthSuccessExportFormat.Csv);

		string[] lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

		// 1 header + 2 logins.
		Assert.Equal(3, lines.Length);
		Assert.StartsWith("NormalizedUserName,DisplayUserName,Domain,AttackerIp,HasSuccess", lines[0], StringComparison.Ordinal);
		Assert.Contains("FailedBeforeFirstSuccess", lines[0], StringComparison.Ordinal);
		Assert.Contains("SuccessEventMeanings", lines[0], StringComparison.Ordinal);
		Assert.Contains("administrator", csv, StringComparison.Ordinal);
		Assert.Contains("45.227.254.38", csv, StringComparison.Ordinal);
	}

	// ── Event-meaning helper ─────────────────────────────────────────────────────

	[Theory]
	[InlineData(4624, "successful logon")]
	[InlineData(4768, "Kerberos TGT")]
	[InlineData(4776, "NTLM credential validation")]
	public void SuccessEventMeaning_DecodesCoreEvents(int eventId, string expectedFragment)
	{
		string meaning = AuthSuccessExportFormatter.SuccessEventMeaning(eventId);
		Assert.Contains(expectedFragment, meaning, StringComparison.OrdinalIgnoreCase);
	}

	// ── File-naming helpers ─────────────────────────────────────────────────────────

	[Theory]
	[InlineData(AuthSuccessExportFormat.Json, ".json")]
	[InlineData(AuthSuccessExportFormat.Txt, ".txt")]
	[InlineData(AuthSuccessExportFormat.Markdown, ".md")]
	[InlineData(AuthSuccessExportFormat.Csv, ".csv")]
	public void GetFileExtension_MatchesFormat(AuthSuccessExportFormat format, string expected)
	{
		Assert.Equal(expected, AuthSuccessExportFormatter.GetFileExtension(format));
	}

	[Fact]
	public void GetDefaultFileName_SanitisesIpAndCarriesExtension()
	{
		string name = AuthSuccessExportFormatter.GetDefaultFileName(
			SampleDto(), AuthSuccessExportFormat.Csv, new DateTime(2026, 6, 20, 10, 0, 0, DateTimeKind.Utc));

		Assert.StartsWith("rdpaudit-auth-success-", name, StringComparison.Ordinal);
		Assert.EndsWith(".csv", name, StringComparison.Ordinal);
	}
}
