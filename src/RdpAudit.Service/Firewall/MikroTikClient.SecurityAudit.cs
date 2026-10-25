// File:    src/RdpAudit.Service/Firewall/MikroTikClient.SecurityAudit.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: The read side of the RouterOS security audit: walks the menus the catalogue needs over the
//          same authenticated REST channel the provider already uses, and hands back a
//          MikroTikSecuritySnapshot. Nothing is written to the router on this path — the audit is
//          read-only by construction.
//
//          Deliberate choices:
//          • system/resource is read first as the probe. If it fails, the run stops with the transport
//            error instead of producing thirty S-00 findings: a broken channel is one fact, not 33.
//          • A menu that answers 404 / "no such command" is recorded as unavailable (the package is
//            absent) and is NOT a finding; the report lists it, so silence still reads as silence.
//          • Any other failure is recorded per menu and surfaced as S-00 by the evaluator.
//          • A total budget bounds the walk: the audit is a UI action, and a router that answers in
//            eight seconds per menu must not hold the IPC call open for four minutes.
// Extends: RdpAudit.Service.Firewall.MikroTikClient (partial)
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using RdpAudit.Core.Config;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.MikroTik.SecurityAudit;

namespace RdpAudit.Service.Firewall;

public sealed partial class MikroTikClient
{
	/// <summary>Upper bound on one field value copied into the snapshot; the audit reads scalars only.</summary>
	private const int SnapshotFieldValueMaxChars = 512;

	/// <summary>Wall-clock budget for the whole menu walk.</summary>
	private static readonly TimeSpan SnapshotBudget = TimeSpan.FromSeconds(45);

	/// <summary>Bodies RouterOS returns for a menu that the installed packages do not provide.</summary>
	private static readonly string[] MissingMenuMarkers =
	[
		"no such command",
		"no such directory",
		"no such command or directory",
		"no such command prefix",
	];

	/// <inheritdoc />
	public async Task<(MikroTikOperationResult Result, MikroTikSecuritySnapshot Snapshot)> ReadSecuritySnapshotAsync(CancellationToken ct)
	{
		DateTime capturedUtc = DateTime.UtcNow;
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		PreparedRequest? prep = Prepare(opts);
		if (prep is null)
		{
			return (
				new MikroTikOperationResult
				{
					Outcome = MikroTikOutcome.NotConfigured,
					Message = "MikroTik provider is not fully configured.",
				},
				MikroTikSecuritySnapshot.Empty(capturedUtc));
		}

		using HttpClient http = CreateHttpClient(opts);
		DateTime startedUtc = DateTime.UtcNow;

		(MikroTikOperationResult probe, string? resourceBody) =
			await GetMenuAsync(http, prep, "system/resource", "Audit.Probe", ct).ConfigureAwait(false);
		if (probe.Outcome != MikroTikOutcome.Accepted)
		{
			_logger.LogInformation(
				"MikroTik security audit stopped at the probe ({Outcome}): {Message}",
				probe.Outcome,
				probe.Message);
			return (probe, MikroTikSecuritySnapshot.Empty(capturedUtc));
		}

		List<Dictionary<string, string>> resourceRows = ParseRows(resourceBody);
		Dictionary<string, string> resource = resourceRows.Count > 0 ? resourceRows[0] : new Dictionary<string, string>(StringComparer.Ordinal);

		(MikroTikOperationResult identityResult, string? identityBody) =
			await GetMenuAsync(http, prep, "system/identity", "Audit.Identity", ct).ConfigureAwait(false);
		List<Dictionary<string, string>> identityRows = identityResult.Outcome == MikroTikOutcome.Accepted
			? ParseRows(identityBody)
			: [];
		string deviceName = identityRows.Count > 0 && identityRows[0].TryGetValue("name", out string? name)
			? name ?? string.Empty
			: string.Empty;

		MikroTikSecuritySnapshot snapshot = MikroTikSecuritySnapshot.CreatePasport(
			reachable: true,
			deviceName: deviceName,
			routerOsVersion: FieldOrEmpty(resource, "version"),
			boardName: FieldOrEmpty(resource, "board-name"),
			uptime: FieldOrEmpty(resource, "uptime"),
			capturedUtc: capturedUtc);

		snapshot.AddRows("resource", ToReadOnlyRows(resourceRows));
		if (identityResult.Outcome == MikroTikOutcome.Accepted)
		{
			snapshot.AddRows("identity", ToReadOnlyRows(identityRows));
		}
		else
		{
			ClassifyFailure(snapshot, "identity", identityResult);
		}

		int read = 2;
		foreach (SecurityAuditSection section in SecurityAuditSections.All)
		{
			if (string.Equals(section.Key, "resource", StringComparison.Ordinal)
				|| string.Equals(section.Key, "identity", StringComparison.Ordinal))
			{
				continue;
			}

			ct.ThrowIfCancellationRequested();

			// The budget is a fact of the run, not an excuse: menus it did not reach are recorded as
			// unread (S-00), which is exactly how the report stays honest about its own coverage.
			if (DateTime.UtcNow - startedUtc > SnapshotBudget)
			{
				snapshot.AddError(section.Key, "audit budget exhausted before this menu was read");
				continue;
			}

			(MikroTikOperationResult result, string? body) =
				await GetMenuAsync(http, prep, section.RestPath, "Audit." + section.Key, ct).ConfigureAwait(false);

			if (result.Outcome == MikroTikOutcome.Accepted)
			{
				snapshot.AddRows(section.Key, ToReadOnlyRows(ParseRows(body)));
				read++;
				continue;
			}

			ClassifyFailure(snapshot, section.Key, result);
		}

		_logger.LogInformation(
			"MikroTik security audit snapshot captured: device={Device} menus read={Read} unavailable={Unavailable} errors={Errors}",
			string.IsNullOrEmpty(deviceName) ? "(unnamed)" : deviceName,
			read,
			snapshot.UnavailableMenus.Count,
			snapshot.Errors.Count);

		return (
			new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.Accepted,
				ResponseCode = 200,
				Message = string.Format(
					CultureInfo.InvariantCulture,
					"Read {0} menus; {1} unavailable; {2} failed.",
					read,
					snapshot.UnavailableMenus.Count,
					snapshot.Errors.Count),
			},
			snapshot);
	}

	private async Task<(MikroTikOperationResult Result, string? Body)> GetMenuAsync(
		HttpClient http,
		PreparedRequest prep,
		string restPath,
		string operationTag,
		CancellationToken ct)
	{
		string url = MikroTikUrlBuilder.CombineRestPath(prep.BaseUrl, restPath);
		using HttpRequestMessage message = BuildRequest(HttpMethod.Get, url, prep.AuthHeader);
		return await SendAndClassifyWithBodyAsync(http, message, operationTag, ct).ConfigureAwait(false);
	}

	private static void ClassifyFailure(MikroTikSecuritySnapshot snapshot, string sectionKey, MikroTikOperationResult result)
	{
		if (result.ResponseCode == (int)HttpStatusCode.NotFound || LooksLikeMissingMenu(result.Message))
		{
			snapshot.AddUnavailable(sectionKey);
			return;
		}

		snapshot.AddError(sectionKey, result.Message);
	}

	private static bool LooksLikeMissingMenu(string? message)
	{
		if (string.IsNullOrWhiteSpace(message))
		{
			return false;
		}

		foreach (string marker in MissingMenuMarkers)
		{
			if (message.Contains(marker, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}
		return false;
	}

	/// <summary>Parses one menu body into rows of string fields; unknown shapes yield an empty list.</summary>
	private static List<Dictionary<string, string>> ParseRows(string? body)
	{
		List<Dictionary<string, string>> rows = new();
		if (string.IsNullOrWhiteSpace(body))
		{
			return rows;
		}

		try
		{
			using JsonDocument document = JsonDocument.Parse(body!);
			if (document.RootElement.ValueKind == JsonValueKind.Array)
			{
				foreach (JsonElement element in document.RootElement.EnumerateArray())
				{
					if (element.ValueKind == JsonValueKind.Object)
					{
						rows.Add(Flatten(element));
					}
				}
				return rows;
			}

			if (document.RootElement.ValueKind == JsonValueKind.Object)
			{
				rows.Add(Flatten(document.RootElement));
			}
			return rows;
		}
		catch (JsonException)
		{
			return rows;
		}
	}

	private static Dictionary<string, string> Flatten(JsonElement element)
	{
		Dictionary<string, string> row = new(StringComparer.Ordinal);
		foreach (JsonProperty property in element.EnumerateObject())
		{
			row[property.Name] = property.Value.ValueKind switch
			{
				JsonValueKind.String => property.Value.GetString() ?? string.Empty,
				JsonValueKind.True => "true",
				JsonValueKind.False => "false",
				JsonValueKind.Null => string.Empty,
				_ => Clamp(property.Value.GetRawText()),
			};
		}
		return row;
	}

	private static string Clamp(string value)
		=> value.Length <= SnapshotFieldValueMaxChars ? value : value[..SnapshotFieldValueMaxChars];

	private static string FieldOrEmpty(Dictionary<string, string> row, string key)
		=> row.TryGetValue(key, out string? value) ? value ?? string.Empty : string.Empty;

	private static List<IReadOnlyDictionary<string, string>> ToReadOnlyRows(List<Dictionary<string, string>> rows)
		=> rows.Cast<IReadOnlyDictionary<string, string>>().ToList();
}
