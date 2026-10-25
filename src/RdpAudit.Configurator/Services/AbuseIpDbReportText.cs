// File:    src/RdpAudit.Configurator/Services/AbuseIpDbReportText.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Single place that turns an Attack Statistics row into the prepared AbuseIPDB report text
//          the operator pastes into the manual submission form. Reuses the same Core comment builder
//          the service uses for the API so the manual and automated reports never drift. Refuses to
//          prepare text for an IP that must never be reported (local / reserved / whitelisted) and
//          surfaces the exact reason instead, satisfying the "never report local/whitelisted" rule.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Builds the clipboard report text for the manual "Open in AbuseIPDB" action.</summary>
public static class AbuseIpDbReportText
{
	/// <summary>Toast shown after the prepared report text is placed on the clipboard.</summary>
	public const string ClipboardToast = "AbuseIPDB report text copied to clipboard.";

	/// <summary>Outcome of preparing report text for a source IP.</summary>
	/// <param name="Prepared">True when report text was produced and may be copied to the clipboard.</param>
	/// <param name="ReportText">The prepared comment body; empty when not prepared.</param>
	/// <param name="Reason">Machine-readable reason the IP was refused; empty when prepared.</param>
	/// <param name="Classification">Coarse classification of the source IP.</param>
	public readonly record struct PrepareResult(
		bool Prepared,
		string ReportText,
		string Reason,
		IpReportClassification Classification);

	/// <summary>
	/// Prepares the AbuseIPDB report text for the supplied attack-statistics row. The victim / local
	/// host is never named; only the attacker source IP and its observed evidence are included.
	/// </summary>
	/// <param name="dto">Attack-statistics row carrying the evidence. Required.</param>
	/// <param name="isWhitelisted">Optional whitelist predicate (canonical IP -> true when allow-listed).</param>
	public static PrepareResult Prepare(AttackStatEntryDto dto, Func<string, bool>? isWhitelisted = null)
	{
		ArgumentNullException.ThrowIfNull(dto);

		IpReportabilityResult classification = IpReportability.Classify(dto.Ip, isWhitelisted);
		if (!classification.IsReportable)
		{
			return new PrepareResult(false, string.Empty, classification.Reason, classification.Classification);
		}

		AbuseIpDbEvidence evidence = new()
		{
			Ip = dto.Ip,
			Hostname = string.Empty,
			FailedAttempts = dto.Failed,
			SuccessfulLogins = dto.Successful,
			FirstSeenUtc = dto.FirstSeenUtc,
			LastSeenUtc = dto.LastSeenUtc,
			UsernamesAttempted = AbuseIpDbReportWorkerLogins.Parse(dto.Top10AttemptedLogins),
			EvidenceEventIds = DeriveEvidenceEventIds(dto),
		};

		return new PrepareResult(
			true,
			AbuseIpDbCommentBuilder.Build(evidence),
			IpReportability.Reasons.Reportable,
			classification.Classification);
	}

	/// <summary>
	/// Derives the Windows Security event IDs that back the evidence from the observed counts.
	/// 4625 (failed logon) when there were failures; 4776 (NTLM credential validation) alongside
	/// failures; 4624 (successful logon) and 4648 (explicit-credential logon) when there were
	/// successful logons.
	/// </summary>
	internal static IReadOnlyList<int> DeriveEvidenceEventIds(AttackStatEntryDto dto)
	{
		List<int> ids = new(4);
		if (dto.Failed > 0)
		{
			ids.Add(4625);
			ids.Add(4776);
		}
		if (dto.Successful > 0)
		{
			ids.Add(4624);
			ids.Add(4648);
		}
		return ids;
	}

	/// <summary>Formats the refusal reason for the status strip when an IP must not be reported.</summary>
	public static string FormatRefusal(string ip, PrepareResult result) => string.Format(
		CultureInfo.InvariantCulture,
		"AbuseIPDB report skipped for {0}: {1} ({2}).",
		string.IsNullOrWhiteSpace(ip) ? "(blank)" : ip,
		result.Reason,
		result.Classification);
}

/// <summary>Parses the persisted Top-10 attempted-login JSON the same way the service worker does.</summary>
internal static class AbuseIpDbReportWorkerLogins
{
	/// <summary>Deserializes a JSON string array of usernames; returns an empty list on any error.</summary>
	public static List<string> Parse(string? json)
	{
		if (string.IsNullOrWhiteSpace(json))
		{
			return new List<string>();
		}
		try
		{
			string[]? parsed = System.Text.Json.JsonSerializer.Deserialize<string[]>(json);
			return parsed is null ? new List<string>() : new List<string>(parsed);
		}
		catch (System.Text.Json.JsonException)
		{
			return new List<string>();
		}
	}
}
