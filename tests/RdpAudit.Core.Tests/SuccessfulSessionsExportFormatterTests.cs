// File:    tests/RdpAudit.Core.Tests/SuccessfulSessionsExportFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the SuccessfulSessionsExportFormatter contract across JSON / TXT / Markdown /
//          CSV: only genuinely successful sessions are included, non-successful facts (pure
//          failures) are excluded, and every rendered format carries the decision evidence
//          (the decoded event ids the success verdict was based on). Also locks the file-naming
//          and IsSuccessful predicate helpers.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Coverage for the "Export Successful RDP Sessions" formatter.</summary>
public class SuccessfulSessionsExportFormatterTests
{
	// ── Sample data ──────────────────────────────────────────────────────────────

	/// <summary>Builds a DTO with one successful session (4624 + 1149), one reconnect-only
	/// success (timestamp evidence), and one pure-failure fact that must be excluded.</summary>
	private static ConnectionFactsForIpDto SampleDto() => new()
	{
		Status = IpcResultStatus.Success,
		Ip = "45.227.254.38",
		QueriedUtc = new DateTime(2026, 6, 20, 10, 0, 0, DateTimeKind.Utc),
		HasActiveFact = true,
		FailedLogons = 169,
		SuccessfulLogons = 2,
		Facts = new List<ConnectionFactDto>
		{
			new()
			{
				Id = 1,
				Ip = "45.227.254.38",
				UserName = "administrator",
				Domain = "CORP",
				WtsSessionId = 3,
				LogonId = "0x3E7",
				FirstSeenUtc = new DateTime(2026, 6, 20, 9, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 6, 20, 9, 14, 0, DateTimeKind.Utc),
				ConnectedUtc = new DateTime(2026, 6, 20, 9, 1, 0, DateTimeKind.Utc),
				AuthenticatedUtc = new DateTime(2026, 6, 20, 9, 1, 5, DateTimeKind.Utc),
				FailedLogons = 0,
				SuccessfulLogons = 1,
				ObservedEventIds = "4624,1149",
				IsActive = true,
			},
			new()
			{
				Id = 2,
				Ip = "45.227.254.38",
				UserName = "svc_backup",
				Domain = "CORP",
				WtsSessionId = 5,
				LogonId = "0x4A1",
				FirstSeenUtc = new DateTime(2026, 6, 20, 9, 20, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 6, 20, 9, 25, 0, DateTimeKind.Utc),
				ReconnectedUtc = new DateTime(2026, 6, 20, 9, 21, 0, DateTimeKind.Utc),
				FailedLogons = 0,
				SuccessfulLogons = 0,
				ObservedEventIds = "25",
				IsActive = false,
			},
			new()
			{
				Id = 3,
				Ip = "45.227.254.38",
				UserName = "maria",
				Domain = null,
				WtsSessionId = null,
				LogonId = null,
				FirstSeenUtc = new DateTime(2026, 6, 20, 9, 30, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 6, 20, 9, 40, 0, DateTimeKind.Utc),
				FailedLogons = 120,
				SuccessfulLogons = 0,
				ObservedEventIds = "4625",
				IsActive = false,
			},
		},
	};

	// ── IsSuccessful predicate ─────────────────────────────────────────────────────

	[Fact]
	public void IsSuccessful_SuccessfulLogons_ReturnsTrue()
	{
		ConnectionFactDto fact = new() { SuccessfulLogons = 1 };
		Assert.True(SuccessfulSessionsExportFormatter.IsSuccessful(fact));
	}

	[Fact]
	public void IsSuccessful_ReconnectTimestampOnly_ReturnsTrue()
	{
		ConnectionFactDto fact = new()
		{
			SuccessfulLogons = 0,
			ReconnectedUtc = new DateTime(2026, 6, 20, 9, 21, 0, DateTimeKind.Utc),
		};
		Assert.True(SuccessfulSessionsExportFormatter.IsSuccessful(fact));
	}

	[Fact]
	public void IsSuccessful_PureFailure_ReturnsFalse()
	{
		ConnectionFactDto fact = new() { SuccessfulLogons = 0, FailedLogons = 120 };
		Assert.False(SuccessfulSessionsExportFormatter.IsSuccessful(fact));
	}

	// ── JSON ─────────────────────────────────────────────────────────────────────

	[Fact]
	public void FormatJson_IncludesOnlySuccessfulSessionsWithEvidence()
	{
		string json = SuccessfulSessionsExportFormatter.Format(SampleDto(), SuccessfulSessionsExportFormat.Json);

		using JsonDocument doc = JsonDocument.Parse(json);
		JsonElement root = doc.RootElement;

		Assert.Equal(2, root.GetProperty("successfulSessionCount").GetInt32());
		Assert.Equal(3, root.GetProperty("totalFactsReturned").GetInt32());

		JsonElement sessions = root.GetProperty("sessions");
		Assert.Equal(2, sessions.GetArrayLength());

		// The excluded pure-failure user must not appear anywhere in the payload.
		Assert.DoesNotContain("maria", json, System.StringComparison.OrdinalIgnoreCase);

		// Decision evidence must be present and decoded.
		JsonElement first = sessions[0];
		JsonElement evidence = first.GetProperty("decisionEvidence");
		Assert.True(evidence.GetArrayLength() >= 1);
		Assert.Contains("4624", json, System.StringComparison.Ordinal);
	}

	// ── TXT ──────────────────────────────────────────────────────────────────────

	[Fact]
	public void FormatTxt_ContainsSuccessfulUsersAndEvidenceButNotFailures()
	{
		string txt = SuccessfulSessionsExportFormatter.Format(SampleDto(), SuccessfulSessionsExportFormat.Txt);

		Assert.Contains("administrator", txt, System.StringComparison.Ordinal);
		Assert.Contains("svc_backup", txt, System.StringComparison.Ordinal);
		Assert.DoesNotContain("maria", txt, System.StringComparison.Ordinal);
		Assert.Contains("Decision", txt, System.StringComparison.Ordinal);
		Assert.Contains("Successful sessions: 2", txt, System.StringComparison.Ordinal);
	}

	[Fact]
	public void FormatTxt_NoSuccessfulSessions_RendersEmptyNotice()
	{
		ConnectionFactsForIpDto dto = SampleDto();
		dto.Facts = new List<ConnectionFactDto>
		{
			new() { Id = 9, Ip = dto.Ip, SuccessfulLogons = 0, FailedLogons = 5, ObservedEventIds = "4625" },
		};

		string txt = SuccessfulSessionsExportFormatter.Format(dto, SuccessfulSessionsExportFormat.Txt);

		Assert.Contains("no successful RDP sessions", txt, System.StringComparison.OrdinalIgnoreCase);
	}

	// ── Markdown ───────────────────────────────────────────────────────────────────

	[Fact]
	public void FormatMarkdown_HasTableHeaderAndSuccessfulRowsOnly()
	{
		string md = SuccessfulSessionsExportFormatter.Format(SampleDto(), SuccessfulSessionsExportFormat.Markdown);

		Assert.Contains("| # | Fact Id |", md, System.StringComparison.Ordinal);
		Assert.Contains("administrator", md, System.StringComparison.Ordinal);
		Assert.Contains("svc_backup", md, System.StringComparison.Ordinal);
		Assert.DoesNotContain("maria", md, System.StringComparison.Ordinal);
	}

	// ── CSV ──────────────────────────────────────────────────────────────────────

	[Fact]
	public void FormatCsv_HeaderPlusOneRowPerSuccessfulSession()
	{
		string csv = SuccessfulSessionsExportFormatter.Format(SampleDto(), SuccessfulSessionsExportFormat.Csv);

		string[] lines = csv.Split('\n', System.StringSplitOptions.RemoveEmptyEntries);

		// 1 header + 2 successful sessions.
		Assert.Equal(3, lines.Length);
		Assert.StartsWith("Id,Ip,UserName", lines[0], System.StringComparison.Ordinal);
		Assert.Contains("DecisionEvidence", lines[0], System.StringComparison.Ordinal);
		Assert.DoesNotContain("maria", csv, System.StringComparison.Ordinal);
	}

	// ── File-naming helpers ─────────────────────────────────────────────────────────

	[Theory]
	[InlineData(SuccessfulSessionsExportFormat.Json, ".json")]
	[InlineData(SuccessfulSessionsExportFormat.Txt, ".txt")]
	[InlineData(SuccessfulSessionsExportFormat.Markdown, ".md")]
	[InlineData(SuccessfulSessionsExportFormat.Csv, ".csv")]
	public void GetFileExtension_MatchesFormat(SuccessfulSessionsExportFormat format, string expected)
	{
		Assert.Equal(expected, SuccessfulSessionsExportFormatter.GetFileExtension(format));
	}

	[Fact]
	public void GetDefaultFileName_SanitisesIpAndCarriesExtension()
	{
		string name = SuccessfulSessionsExportFormatter.GetDefaultFileName(
			SampleDto(), SuccessfulSessionsExportFormat.Csv, new DateTime(2026, 6, 20, 10, 0, 0, DateTimeKind.Utc));

		Assert.StartsWith("rdpaudit-successful-sessions-", name, System.StringComparison.Ordinal);
		Assert.EndsWith(".csv", name, System.StringComparison.Ordinal);
	}
}
