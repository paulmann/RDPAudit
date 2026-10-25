// File:    src/RdpAudit.Service/Services/PurgeBySubjectService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Deletes every evidence row that belongs to one subject - a single address, a CIDR range, a login
//          or a UTC time window - across the tables that carry that dimension (IpcCommand.PurgeBySubject,
//          ordinal 94).
//          Three properties are load-bearing and every one of them is enforced here, on the server, never
//          on the client:
//            1. A DRY RUN IS THE DEFAULT AND PREDICTS EXACTLY. The preview and the apply pass build their
//               WHERE clause with the same code, so "would delete 4123 rows" and "deleted 4123 rows" are
//               the same computation, not two estimates that happen to agree.
//            2. APPLYING NEEDS THE TYPED PHRASE, AND A LEGAL HOLD BLOCKS IT OUTRIGHT. A legal hold is not
//               an override-with-a-warning: while it is in force this path removes no evidence at all. The
//               dry run still reports the frozen counts so the operator can see the size of what is held.
//            3. NOTHING LEAVES WITHOUT A LEDGER ROW ON THE HASH CHAIN. The ledger entry for a table is
//               appended inside the transaction of the batch that finished deleting that table, through the
//               same chain writer the retention engine uses, so the deletion and its tombstone commit
//               together and a doctored ledger breaks the chain.
//          What is deliberately NOT touched, and reported as such in every response: the schema, the EF
//          migration history, DbProps, event-log bookmarks, the append-only ledger itself, the audit
//          journal, and the operator's own configuration and enforcement state (blocklist, whitelist, login
//          rules, active blocks). Deleting an operator's blocklist entry as a side effect of a subject
//          purge would silently change enforcement, which is a different act than removing evidence and
//          must be requested as such.
//          Bounded work: deletes run in batches of at most ResolveDeleteBatchRows() inside short
//          transactions, a whole run is capped at MaxTotalRowsPerRun, and every batch is cancellable.
// Extends: System.Object

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;

namespace RdpAudit.Service.Services;

/// <summary>One table a subject purge may delete from, with the column that carries each dimension. A table
/// appears here only when the subject can be expressed against it.</summary>
internal sealed record SubjectTarget(
	string Table,
	string? IpBinaryColumn,
	string? IpTextColumn,
	IReadOnlyList<string> LoginColumns,
	string TimestampColumn,
	bool TimestampIsTicks);

/// <summary>The resolved subject: canonical address bytes, a range, a login, and/or a window.</summary>
internal sealed class SubjectMatch
{
	/// <summary>Dimension this subject was expressed in.</summary>
	internal PurgeSubjectKind Kind { get; init; }

	/// <summary>Canonical display text for the report and the ledger reason.</summary>
	internal string Display { get; init; } = string.Empty;

	/// <summary>Canonical 16-byte address for a single-address subject; null otherwise.</summary>
	internal byte[]? IpBinary16 { get; init; }

	/// <summary>Canonical text address for a single-address subject; null otherwise.</summary>
	internal string? IpText { get; init; }

	/// <summary>Inclusive first address of a CIDR range; null for other kinds.</summary>
	internal byte[]? RangeStart { get; init; }

	/// <summary>Inclusive last address of a CIDR range; null for other kinds.</summary>
	internal byte[]? RangeEnd { get; init; }

	/// <summary>Text-form addresses inside the CIDR range, resolved from the store's own address keys so
	/// the text-keyed tables are reachable for a range purge. Bounded by
	/// <see cref="PurgeBySubjectService.MaxCidrAddressExpansion"/>.</summary>
	internal List<string> RangeTextIps { get; } = [];

	/// <summary>Login subject; null otherwise.</summary>
	internal string? Login { get; init; }

	/// <summary>Window lower bound, inclusive, when one applies.</summary>
	internal DateTime? WindowStartUtc { get; init; }

	/// <summary>Window upper bound, exclusive, when one applies.</summary>
	internal DateTime? WindowEndUtc { get; init; }

	internal static SubjectMatch ForAddress(byte[] binary, string canonical, DateTime? start, DateTime? end) => new()
	{
		Kind = PurgeSubjectKind.Ip,
		Display = canonical,
		IpBinary16 = binary,
		IpText = canonical,
		WindowStartUtc = start,
		WindowEndUtc = end,
	};

	internal static SubjectMatch ForRange(byte[] start, byte[] end, string display, DateTime? from, DateTime? to) => new()
	{
		Kind = PurgeSubjectKind.Cidr,
		Display = display,
		RangeStart = start,
		RangeEnd = end,
		WindowStartUtc = from,
		WindowEndUtc = to,
	};

	internal static SubjectMatch ForLogin(string login, DateTime? start, DateTime? end) => new()
	{
		Kind = PurgeSubjectKind.Login,
		Display = login,
		Login = login,
		WindowStartUtc = start,
		WindowEndUtc = end,
	};

	internal static SubjectMatch ForWindow(DateTime start, DateTime end) => new()
	{
		Kind = PurgeSubjectKind.TimeRange,
		Display = string.Create(
			CultureInfo.InvariantCulture,
			$"{start:O}..{end:O}"),
		WindowStartUtc = start,
		WindowEndUtc = end,
	};
}

/// <summary>A composed WHERE clause and its parameters.</summary>
internal sealed record SubjectPredicate(string Where, IReadOnlyList<SqliteParameter> Parameters)
{
	/// <summary>False when this table carries none of the subject's dimensions, in which case the only
	/// honest answer is "no rows in scope" rather than a predicate that matches everything.</summary>
	internal bool IsApplicable => Where.Length > 0;
}

/// <summary>Applies or previews a subject-scoped evidence purge with a mandatory dry run, a server-side
/// typed phrase, legal-hold enforcement and hash-chained ledger accountability.</summary>
public sealed class PurgeBySubjectService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>The exact phrase an apply pass must carry. Re-validated here, on the server, so a client
	/// that skips its own confirmation dialog still cannot delete anything.</summary>
	public const string ConfirmationPhrase = "PURGE SUBJECT DATA";

	/// <summary>Hard ceiling on rows one run may delete. The per-table batches bound the writer lock; this
	/// bounds the whole operation, so a mistyped window cannot turn into an hours-long delete. A run that
	/// hits it stops cleanly and says so - it is never silently truncated.</summary>
	internal const long MaxTotalRowsPerRun = 5_000_000;

	/// <summary>Ceiling on how many distinct addresses a CIDR is expanded into for the text-keyed tables.
	/// A range that matches more known addresses than this is refused rather than half-purged, because a
	/// partial purge of a CIDR is indistinguishable from a complete one in the report.</summary>
	internal const int MaxCidrAddressExpansion = 4096;

	/// <summary>Rule name recorded on a subject-purge ledger row: an operator decision, not a versioned
	/// retention rule, and the reason text says so.</summary>
	private const string PurgeRuleName = "PurgeBySubject";

	/// <summary>System surfaces no subject purge may touch, reported verbatim in every response so the
	/// choice is visible instead of implied by absence.</summary>
	internal static readonly string[] PreservedSystemSurfaces =
	[
		"Schema and __EFMigrationsHistory (a purge must never make the service unable to start)",
		"DbProps (configuration and migration state)",
		"Bookmarks (event-log read positions; clearing them would re-read the whole Security log)",
		"EventDeletionLedger (append-only: a purge ADDS ledger rows, it never removes them)",
		"OperationLogs and DatabaseIntegrityCheckResult (audit records)",
		"BlocklistEntries, WhitelistEntries and LoginRules (operator configuration)",
		"ActiveBlocks (enforcement state; unblock or reconcile it as an enforcement action)",
	];

	/// <summary>The tables a subject purge may delete from. Anything absent is either a preserved system
	/// surface or carries no such dimension; both are reported as untouched rather than omitted.</summary>
	internal static readonly SubjectTarget[] Targets =
	[
		new("RawEvents", "SourceIpBinary", "SourceIp", ["UserName"], "TimeUtc", TimestampIsTicks: false),
		new("AuthAttemptFacts", null, "SourceIp", ["TargetUser", "NormalizedUserName"], "TimeUtc", TimestampIsTicks: false),
		new("RdpConnectionFacts", null, "Ip", ["UserName"], "LastSeenUtc", TimestampIsTicks: false),
		new("SessionIpCorrelations", null, "Ip", ["UserName"], "LastSeenUtc", TimestampIsTicks: false),
		new("Sessions", null, "SourceIp", ["UserName"], "ConnectUtc", TimestampIsTicks: false),
		new("Alerts", null, "SourceIp", ["UserName"], "TimeUtc", TimestampIsTicks: false),
		new("Addresses", null, "Ip", [], "LastSeen", TimestampIsTicks: false),
		new("AbuseReports", null, "Ip", [], "ReportedUtc", TimestampIsTicks: false),
		new("AbuseIpDbReportHistory", null, "IpAddress", [], "ReportedAtUtc", TimestampIsTicks: false),
		new("AttackStats", null, "Ip", [], "LastSeenUtc", TimestampIsTicks: false),
		new("ThreatIntelLookups", null, "Ip", [], "LookedUpUtc", TimestampIsTicks: false),
		new("IpEventSummary", "IpBinary16", "IpText", [], "LastEventUtc", TimestampIsTicks: true),
		new("IpEventTypeCounter", "IpBinary16", null, [], "LastUtc", TimestampIsTicks: true),
		new("CrossHostFacts", null, "SourceIp", ["UserName", "NormalizedUserName"], "TimeUtc", TimestampIsTicks: false),
		new("CrossHostLinks", null, "SourceIp", ["UserName"], "TimeUtc", TimestampIsTicks: false),
		new("ProcessObservations", null, null, ["UserName"], "ObservedUtc", TimestampIsTicks: false),
		new("KnownProcesses", null, null, ["UserName"], "LastObservedUtc", TimestampIsTicks: false),
	];

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<PurgeBySubjectService> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the database factory and the live options monitor.</summary>
	public PurgeBySubjectService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<PurgeBySubjectService> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Previews or applies a subject purge. <paramref name="actor"/> is the resolved invoking
	/// identity recorded on every ledger entry.</summary>
	public async Task<PurgeBySubjectReportDto> RunAsync(
		PurgeBySubjectRequest? request,
		string actor,
		CancellationToken cancellationToken)
	{
		PurgeBySubjectReportDto report = new()
		{
			QueriedUtc = DateTime.UtcNow,
			DryRun = true,
			Kind = request?.Kind ?? PurgeSubjectKind.Unknown,
			Preserved = [.. PreservedSystemSurfaces],
		};
		StringBuilder log = new();
		void Trace(string line) => log.Append('[')
			.Append(DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
			.Append("] ").Append(line).Append('\n');

		RetentionPolicyOptions policy = _options.CurrentValue.Storage.RetentionPolicy;
		report.LegalHold = policy.LegalHold;
		Trace(string.Create(
			CultureInfo.InvariantCulture,
			$"PurgeBySubject invoked by {actor}; apply={request?.Apply == true}; legalHold={policy.LegalHold}."));

		if (!TryResolveSubject(request, report, Trace, out SubjectMatch? resolved, out string? validationError))
		{
			report.Status = IpcResultStatus.InvalidRequest;
			report.Message = validationError ?? "The purge request is not valid.";
			report.DebugLog = log.ToString();
			return report;
		}

		SubjectMatch match = resolved!;
		report.Subject = match.Display;
		report.WindowStartUtc = match.WindowStartUtc;
		report.WindowEndUtc = match.WindowEndUtc;

		bool apply = request?.Apply == true;
		if (apply && request is not null && !TryAuthorizeApply(request, policy, report, Trace))
		{
			report.DebugLog = log.ToString();
			await PopulateCountsAsync(report, match, cancellationToken).ConfigureAwait(false);
			report.DebugLog += log.ToString();
			return report;
		}

		if (apply)
		{
			report.DryRun = false;
			report.Applied = true;
		}

		int batchRows = policy.ResolveDeleteBatchRows();
		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
			SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();

			if (match.Kind == PurgeSubjectKind.Cidr)
			{
				if (!await TryResolveRangeTextIpsAsync(connection, match, cancellationToken).ConfigureAwait(false))
				{
					report.Status = IpcResultStatus.Refused;
					report.Message = string.Format(
						CultureInfo.InvariantCulture,
						"REFUSED: the range matches more than {0} known addresses, which is beyond what a bounded "
							+ "purge can cover completely. Narrow the range and run one purge per block. Nothing "
							+ "was deleted.",
						MaxCidrAddressExpansion);
					report.DebugLog = log.ToString();
					return report;
				}

				Trace(string.Create(
					CultureInfo.InvariantCulture,
					$"CIDR expanded to {match.RangeTextIps.Count} known address(es) for the text-keyed tables."));
			}

			foreach (SubjectTarget target in Targets)
			{
				cancellationToken.ThrowIfCancellationRequested();
				PurgeBySubjectTableDto tableResult = new() { Table = target.Table };
				SubjectPredicate predicate = BuildPredicate(match, target);
				if (!predicate.IsApplicable)
				{
					// The table carries none of this subject's dimensions: report zero rather than omit the
					// row and leave the reader to wonder whether it was in scope.
					report.Tables.Add(tableResult);
					continue;
				}

				tableResult.RowsMatched = await CountAsync(connection, target, predicate, cancellationToken)
					.ConfigureAwait(false);

				if (!apply || tableResult.RowsMatched == 0)
				{
					Trace(string.Create(
						CultureInfo.InvariantCulture,
						$"{target.Table}: matched {tableResult.RowsMatched} row(s); deleted 0 (dry run or empty)."));
					report.Tables.Add(tableResult);
					continue;
				}

				long remainingBudget = MaxTotalRowsPerRun - report.Tables.Sum(entry => entry.RowsDeleted);
				if (remainingBudget <= 0)
				{
					Trace("Row budget exhausted; " + target.Table + " was not touched. Re-run to continue.");
					report.Tables.Add(tableResult);
					continue;
				}

				(tableResult.RowsDeleted, tableResult.WindowStartUtc, tableResult.WindowEndUtc, tableResult.LedgerWritten) =
					await DeleteBatchedAsync(
						db,
						connection,
						target,
						predicate,
						Math.Min(batchRows, (int)Math.Min(int.MaxValue, remainingBudget)),
						remainingBudget,
						match,
						actor,
						cancellationToken).ConfigureAwait(false);
				if (tableResult.LedgerWritten)
				{
					report.LedgerEntriesWritten++;
					report.LedgerChainHead = await ReadChainHeadAsync(connection, cancellationToken).ConfigureAwait(false);
				}

				Trace(string.Create(
					CultureInfo.InvariantCulture,
					$"{target.Table}: matched {tableResult.RowsMatched} row(s); deleted {tableResult.RowsDeleted}."));
				report.Tables.Add(tableResult);
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Subject purge failed against {Subject}", match.Display);
			report.Status = IpcResultStatus.Unavailable;
			report.Message = "The subject purge failed: " + ex.GetType().Name + " - " + ex.Message
				+ " Batches that already committed stay deleted and are recorded in the ledger; re-run the "
				+ "purge to finish.";
			Trace("Failure: " + ex.GetType().Name + ": " + ex.Message);
			report.DebugLog = log.ToString();
			return report;
		}

		report.Tables.Sort(static (left, right) => string.CompareOrdinal(left.Table, right.Table));
		report.TotalRowsMatched = report.Tables.Sum(entry => entry.RowsMatched);
		report.TotalRowsDeleted = report.Tables.Sum(entry => entry.RowsDeleted);
		report.Status = IpcResultStatus.Success;
		report.Message = report.Applied
			? string.Format(
				CultureInfo.InvariantCulture,
				"Purged {0} row(s) for subject '{1}' across {2} table(s); {3} ledger entr(ies) appended to the hash chain.",
				report.TotalRowsDeleted,
				report.Subject,
				report.Tables.Count(entry => entry.RowsDeleted > 0),
				report.LedgerEntriesWritten)
			: string.Format(
				CultureInfo.InvariantCulture,
				"DRY RUN for subject '{0}': {1} row(s) across {2} table(s) would be deleted. Nothing was deleted. "
					+ "Re-run with Apply=true and the confirmation phrase to perform it.",
				report.Subject,
				report.TotalRowsMatched,
				report.Tables.Count(entry => entry.RowsMatched > 0));
		Trace("Result: " + report.Message);
		report.DebugLog = log.ToString();
		_logger.LogInformation(
			"Subject purge {Mode}: subject={Subject} kind={Kind} matched={Matched} deleted={Deleted} ledger={Ledger}",
			report.Applied ? "applied" : "dry-run",
			report.Subject,
			report.Kind,
			report.TotalRowsMatched,
			report.TotalRowsDeleted,
			report.LedgerEntriesWritten);
		return report;
	}

	private static bool TryAuthorizeApply(
		PurgeBySubjectRequest request,
		RetentionPolicyOptions policy,
		PurgeBySubjectReportDto report,
		Action<string> trace)
	{
		// Two independent barriers, both server-side: the legal hold first, because it is a statement about
		// authority, then the phrase, because it is a statement about intent.
		if (policy.LegalHold)
		{
			report.Status = IpcResultStatus.Refused;
			report.Message =
				"REFUSED: a legal hold is in force (RdpAudit:Storage:RetentionPolicy:LegalHold), so no evidence "
				+ "may be removed by a subject purge. Clear the hold first; the counts below show the frozen rows.";
			trace("Apply refused: legal hold in force.");
			return false;
		}

		if (!string.Equals(request.ConfirmationPhrase, ConfirmationPhrase, StringComparison.Ordinal))
		{
			report.Status = IpcResultStatus.Refused;
			report.Message =
				"REFUSED: the confirmation phrase did not match, so nothing was deleted. The phrase is re-checked "
				+ "on the server; a client that skips its own confirmation dialog cannot delete anything.";
			trace("Apply refused: confirmation phrase mismatch.");
			return false;
		}

		return true;
	}

	// ── Subject resolution ───────────────────────────────────────────────────────

	/// <summary>Resolves and validates the request into a canonical subject. Every rejection carries a
	/// specific reason, because "invalid request" on a destructive command is not actionable.</summary>
	private static bool TryResolveSubject(
		PurgeBySubjectRequest? request,
		PurgeBySubjectReportDto report,
		Action<string> trace,
		out SubjectMatch? subject,
		out string? error)
	{
		subject = null;
		error = null;

		if (request is null || !Enum.IsDefined(request.Kind) || request.Kind == PurgeSubjectKind.Unknown)
		{
			error = "PurgeBySubject requires a subject kind: Ip, Cidr, Login or TimeRange.";
			return false;
		}

		DateTime? start = request.WindowStartUtc;
		DateTime? end = request.WindowEndUtc;
		if (start is not null && end is not null && end <= start)
		{
			error = "The window end must be later than the window start (the end bound is exclusive).";
			return false;
		}

		switch (request.Kind)
		{
			case PurgeSubjectKind.TimeRange:
				if (start is null || end is null)
				{
					error = "TimeRange requires both WindowStartUtc and WindowEndUtc. A range with one open end "
						+ "would silently delete everything older or newer than a single bound.";
					return false;
				}

				subject = SubjectMatch.ForWindow(start.Value, end.Value);
				return true;

			case PurgeSubjectKind.Ip:
				string addressText = request.Value?.Trim() ?? string.Empty;
				if (addressText.Length == 0)
				{
					error = "Ip requires an address.";
					return false;
				}

				if (!IPAddress.TryParse(addressText, out IPAddress? address))
				{
					error = "'" + addressText + "' is not a valid IP address.";
					return false;
				}

				subject = SubjectMatch.ForAddress(ToCanonicalBytes(address), address.ToString(), start, end);
				return true;

			case PurgeSubjectKind.Cidr:
				if (!TryParseCidr(request.Value, out byte[] rangeStart, out byte[] rangeEnd, out string? cidrError))
				{
					error = cidrError;
					return false;
				}

				subject = SubjectMatch.ForRange(rangeStart, rangeEnd, request.Value!.Trim(), start, end);
				return true;

			case PurgeSubjectKind.Login:
				string login = request.Value?.Trim() ?? string.Empty;
				if (login.Length == 0)
				{
					error = "Login requires a non-empty login name.";
					return false;
				}

				if (login.Length > 256)
				{
					error = "The login name is longer than the 256-character column it would be matched against.";
					return false;
				}

				trace(string.Create(CultureInfo.InvariantCulture, $"Resolved login subject '{login}' (case-insensitive)."));
				subject = SubjectMatch.ForLogin(login, start, end);
				return true;

			default:
				error = "Unsupported subject kind: " + report.Kind + ".";
				return false;
		}
	}

	/// <summary>Parses a CIDR range into its inclusive 16-byte bounds. Both bounds live in the same address
	/// family in the canonical big-endian form, so a byte-wise <c>BETWEEN</c> selects exactly the range -
	/// which is what makes the binary-keyed tables reachable for a range purge at all.</summary>
	private static bool TryParseCidr(
		string? value,
		out byte[] rangeStart,
		out byte[] rangeEnd,
		out string? error)
	{
		rangeStart = [];
		rangeEnd = [];
		error = null;

		string text = value?.Trim() ?? string.Empty;
		int slash = text.IndexOf('/', StringComparison.Ordinal);
		if (slash <= 0 || slash == text.Length - 1)
		{
			error = "'" + text + "' is not a CIDR range; use the form 203.0.113.0/24.";
			return false;
		}

		if (!IPAddress.TryParse(text[..slash], out IPAddress? address))
		{
			error = "The network part of '" + text + "' is not a valid IP address.";
			return false;
		}

		if (!int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out int prefix))
		{
			error = "The prefix length of '" + text + "' is not a number.";
			return false;
		}

		bool isV6 = address.AddressFamily == AddressFamily.InterNetworkV6;
		if (!isV6 && address.IsIPv4MappedToIPv6)
		{
			// An operator who wrote ::ffff:203.0.113.0/120 meant the IPv4 block; normalize to IPv4 first.
			address = address.MapToIPv4();
		}

		int bitLength = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
		if (prefix < 0 || prefix > bitLength)
		{
			error = string.Create(
				CultureInfo.InvariantCulture,
				$"The prefix length {prefix} is outside 0..{bitLength} for this address family.");
			return false;
		}

		if (prefix == 0)
		{
			error = "A /0 range covers the whole internet and is refused as a subject purge. Narrow the range.";
			return false;
		}

		// Mask in the 128-bit space the column actually stores: an IPv4 prefix sits after the 96-bit
		// IPv4-mapped prefix.
		int mappedPrefix = address.AddressFamily == AddressFamily.InterNetwork ? prefix + 96 : prefix;
		byte[] startBytes = ToCanonicalBytes(address);
		byte[] endBytes = (byte[])startBytes.Clone();
		for (int index = 0; index < 16; index++)
		{
			int bits = Math.Clamp(mappedPrefix - (index * 8), 0, 8);
			byte mask = bits == 0 ? (byte)0 : (byte)(0xFF << (8 - bits));
			startBytes[index] &= mask;
			endBytes[index] |= (byte)~mask;
		}

		rangeStart = startBytes;
		rangeEnd = endBytes;
		return true;
	}

	/// <summary>Canonical storage form: IPv6-mapped 16 bytes, matching IpEventSummaryUpserter.</summary>
	private static byte[] ToCanonicalBytes(IPAddress address)
		=> address.AddressFamily == AddressFamily.InterNetwork
			? address.MapToIPv6().GetAddressBytes()
			: address.GetAddressBytes();

	/// <summary>Resolves the text-form addresses inside a CIDR range from the store's own address keys, so
	/// the text-keyed tables can be purged by a range. Refuses (returns false) when the range covers more
	/// addresses than the expansion ceiling: a partial range purge would be indistinguishable from a
	/// complete one in the report.</summary>
	private static async Task<bool> TryResolveRangeTextIpsAsync(
		SqliteConnection connection,
		SubjectMatch match,
		CancellationToken cancellationToken)
	{
		if (match.RangeStart is null || match.RangeEnd is null)
		{
			return false;
		}

		List<string> candidates = [];
		await using (SqliteCommand binaryQuery = connection.CreateCommand())
		{
			SetCommandText(
				binaryQuery,
				"SELECT \"IpText\" FROM \"IpEventSummary\" WHERE \"IpBinary16\" >= $from AND \"IpBinary16\" <= $to;");
			binaryQuery.Parameters.AddWithValue("$from", match.RangeStart);
			binaryQuery.Parameters.AddWithValue("$to", match.RangeEnd);
			await using SqliteDataReader reader = await binaryQuery.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
			while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
			{
				if (!reader.IsDBNull(0))
				{
					candidates.Add(reader.GetString(0));
					if (candidates.Count > MaxCidrAddressExpansion)
					{
						return false;
					}
				}
			}
		}

		await using (SqliteCommand textQuery = connection.CreateCommand())
		{
			// Addresses has no binary column, so every row is parsed here and compared in memory. The table
			// is keyed by address, which bounds it by the number of distinct sources the host has seen.
			SetCommandText(textQuery, "SELECT \"Ip\" FROM \"Addresses\";");
			await using SqliteDataReader reader = await textQuery.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
			while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
			{
				cancellationToken.ThrowIfCancellationRequested();
				if (reader.IsDBNull(0))
				{
					continue;
				}

				string text = reader.GetString(0);
				if (candidates.Contains(text, StringComparer.Ordinal)
					|| !IPAddress.TryParse(text, out IPAddress? address))
				{
					continue;
				}

				if (IsInRange(ToCanonicalBytes(address), match.RangeStart, match.RangeEnd))
				{
					candidates.Add(text);
					if (candidates.Count > MaxCidrAddressExpansion)
					{
						return false;
					}
				}
			}
		}

		match.RangeTextIps.AddRange(candidates);
		return true;
	}

	private static bool IsInRange(byte[] value, byte[] rangeStart, byte[] rangeEnd)
	{
		if (value.Length != rangeStart.Length || value.Length != rangeEnd.Length)
		{
			return false;
		}

		return value.AsSpan().SequenceCompareTo(rangeStart.AsSpan()) >= 0
			&& value.AsSpan().SequenceCompareTo(rangeEnd.AsSpan()) <= 0;
	}

	// ── Predicates ───────────────────────────────────────────────────────────────

	/// <summary>Builds the WHERE clause for one table. Written once and used by both the count (dry run)
	/// and the delete, which is what makes the dry run a prediction rather than an estimate.</summary>
	internal static SubjectPredicate BuildPredicate(SubjectMatch match, SubjectTarget target)
	{
		List<string> clauses = new(4);
		List<SqliteParameter> parameters = new(8);

		switch (match.Kind)
		{
			case PurgeSubjectKind.Ip:
				if (target.IpBinaryColumn is { } binaryColumn)
				{
					clauses.Add("\"" + binaryColumn + "\" = $subjectIpBinary");
					parameters.Add(new SqliteParameter("$subjectIpBinary", match.IpBinary16));
				}

				if (target.IpTextColumn is { } textColumn)
				{
					clauses.Add("\"" + textColumn + "\" = $subjectIpText");
					parameters.Add(new SqliteParameter("$subjectIpText", match.IpText));
				}

				break;

			case PurgeSubjectKind.Cidr:
				if (target.IpBinaryColumn is { } rangeBinaryColumn)
				{
					// BLOB comparison in SQLite is memcmp and the canonical form is big-endian, so BETWEEN
					// over the 16 bytes is exactly the address range.
					clauses.Add(
						"(\"" + rangeBinaryColumn + "\" >= $subjectRangeFrom AND \""
							+ rangeBinaryColumn + "\" <= $subjectRangeTo)");
					parameters.Add(new SqliteParameter("$subjectRangeFrom", match.RangeStart));
					parameters.Add(new SqliteParameter("$subjectRangeTo", match.RangeEnd));
				}

				if (target.IpTextColumn is { } rangeTextColumn && match.RangeTextIps.Count > 0)
				{
					StringBuilder inList = new("(\"" + rangeTextColumn + "\" IN (");
					for (int index = 0; index < match.RangeTextIps.Count; index++)
					{
						if (index > 0)
						{
							inList.Append(',');
						}

						string parameterName = "$subjectRangeText" + index.ToString(CultureInfo.InvariantCulture);
						inList.Append(parameterName);
						parameters.Add(new SqliteParameter(parameterName, match.RangeTextIps[index]));
					}

					inList.Append("))");
					clauses.Add(inList.ToString());
				}

				break;

			case PurgeSubjectKind.Login:
				foreach (string loginColumn in target.LoginColumns)
				{
					// Windows logins are case-insensitive; matching them case-sensitively would leave rows
					// behind that the operator believes they purged.
					clauses.Add("\"" + loginColumn + "\" = $subjectLogin COLLATE NOCASE");
				}

				if (target.LoginColumns.Count > 0)
				{
					parameters.Add(new SqliteParameter("$subjectLogin", match.Login));
				}

				break;

			case PurgeSubjectKind.TimeRange:
			default:
				break;
		}

		if (match.WindowStartUtc is not null && match.WindowEndUtc is not null)
		{
			if (target.TimestampIsTicks)
			{
				clauses.Add(
					"\"" + target.TimestampColumn + "\" >= $subjectFromTicks AND \""
						+ target.TimestampColumn + "\" < $subjectToTicks");
				parameters.Add(new SqliteParameter("$subjectFromTicks", match.WindowStartUtc.Value.Ticks));
				parameters.Add(new SqliteParameter("$subjectToTicks", match.WindowEndUtc.Value.Ticks));
			}
			else
			{
				clauses.Add(
					"\"" + target.TimestampColumn + "\" >= $subjectWindowStart AND \""
						+ target.TimestampColumn + "\" < $subjectWindowEnd");
				parameters.Add(new SqliteParameter("$subjectWindowStart", match.WindowStartUtc.Value));
				parameters.Add(new SqliteParameter("$subjectWindowEnd", match.WindowEndUtc.Value));
			}
		}

		return new SubjectPredicate(
			clauses.Count == 0 ? string.Empty : string.Join(" AND ", clauses),
			parameters);
	}

	// ── Counting and deleting ────────────────────────────────────────────────────

	private static async Task<long> CountAsync(
		SqliteConnection connection,
		SubjectTarget target,
		SubjectPredicate predicate,
		CancellationToken cancellationToken)
	{
		using SqliteCommand command = connection.CreateCommand();
		SetCommandText(
			command,
			"SELECT COUNT(*) FROM \"" + target.Table + "\" WHERE " + predicate.Where + ";");
		AddSubjectParameters(command, predicate);
		object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return value is long count ? count : 0L;
	}

	/// <summary>Deletes matching rows in bounded batches, one transaction per batch, and appends the table's
	/// hash-chained ledger row inside the transaction of the batch that finished the deletion, so the
	/// deletion and its tombstone commit together.</summary>
	private static async Task<(long Deleted, DateTime? WindowStart, DateTime? WindowEnd, bool LedgerWritten)>
		DeleteBatchedAsync(
			AuditDbContext db,
			SqliteConnection connection,
			SubjectTarget target,
			SubjectPredicate predicate,
			int batchRows,
			long budget,
			SubjectMatch match,
			string actor,
			CancellationToken cancellationToken)
	{
		string where = predicate.Where;
		long deleted = 0;
		DateTime? observedStart = null;
		DateTime? observedEnd = null;
		bool ledgerWritten = false;

		while (deleted < budget)
		{
			cancellationToken.ThrowIfCancellationRequested();
			int batch = (int)Math.Min(batchRows, budget - deleted);
			long deletedInBatch;
			await using (IDbContextTransaction transaction =
				await db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false))
			{
				SqliteTransaction sqliteTransaction = (SqliteTransaction)transaction.GetDbTransaction();

				using (SqliteCommand window = connection.CreateCommand())
				{
					window.Transaction = sqliteTransaction;
					SetCommandText(
						window,
						"SELECT MIN(\"" + target.TimestampColumn + "\"), MAX(\"" + target.TimestampColumn
							+ "\") FROM \"" + target.Table + "\" WHERE " + where + ";");
					AddSubjectParameters(window, predicate);
					await using SqliteDataReader reader =
						await window.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
					if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && !reader.IsDBNull(0))
					{
						DateTime batchStart = ReadTimestamp(reader, 0, target.TimestampIsTicks);
						DateTime batchEnd = ReadTimestamp(reader, 1, target.TimestampIsTicks);
						observedStart = observedStart is null || batchStart < observedStart ? batchStart : observedStart;
						observedEnd = observedEnd is null || batchEnd > observedEnd ? batchEnd : observedEnd;
					}
				}

				using (SqliteCommand delete = connection.CreateCommand())
				{
					delete.Transaction = sqliteTransaction;
					SetCommandText(
						delete,
						"DELETE FROM \"" + target.Table + "\" WHERE rowid IN (SELECT rowid FROM \""
							+ target.Table + "\" WHERE " + where + " LIMIT $batchRows);");
					AddSubjectParameters(delete, predicate);
					delete.Parameters.AddWithValue("$batchRows", batch);
					deletedInBatch = await delete.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
				}

				long totalForTable = deleted + deletedInBatch;
				bool lastBatch = deletedInBatch < batch;
				if (lastBatch && totalForTable > 0)
				{
					string previousHash = await EventDeletionLedgerWriter
						.ReadChainHeadAsync(connection, sqliteTransaction, cancellationToken)
						.ConfigureAwait(false);
					LedgerChainEntry entry = new(
						EventCode: 0,
						Scope: (int)(match.IpBinary16 is not null ? EventDeletionScope.PerIp : EventDeletionScope.Global),
						IpBinary16: match.IpBinary16,
						WindowStartUtc: observedStart ?? match.WindowStartUtc ?? DateTime.UtcNow,
						WindowEndUtc: observedEnd ?? match.WindowEndUtc ?? DateTime.UtcNow,
						RowsDeleted: totalForTable,
						Trigger: (int)EventDeletionTrigger.OperatorRequest,
						RuleVersion: RetentionRuleVersion.Current,
						Reason: EventDeletionLedgerWriter.BuildReason(
							PurgeRuleName,
							"OperatorRequest",
							"table=" + target.Table + "; kind=" + match.Kind + "; subject=" + match.Display
								+ "; actor=" + actor),
						InitiatedBy: actor,
						CreatedUtc: DateTime.UtcNow);
					await EventDeletionLedgerWriter
						.AppendAsync(connection, sqliteTransaction, entry, previousHash, cancellationToken)
						.ConfigureAwait(false);
					ledgerWritten = true;
				}

				await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
				deleted = totalForTable;
			}

			if (deletedInBatch < batch)
			{
				break;
			}
		}

		return (deleted, observedStart, observedEnd, ledgerWritten);
	}

	private static DateTime ReadTimestamp(SqliteDataReader reader, int ordinal, bool isTicks)
	{
		object value = reader.GetValue(ordinal);
		if (isTicks)
		{
			return value is long ticks ? new DateTime(ticks, DateTimeKind.Utc) : DateTime.UtcNow;
		}

		return value switch
		{
			DateTime dateTime => dateTime,
			string text => DateTime.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.None),
			_ => DateTime.UtcNow,
		};
	}

	private static async Task<string> ReadChainHeadAsync(SqliteConnection connection, CancellationToken cancellationToken)
	{
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText =
			"SELECT \"EntryHash\" FROM \"EventDeletionLedger\" WHERE \"EntryHash\" IS NOT NULL "
			+ "ORDER BY \"Id\" DESC LIMIT 1;";
		object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return value is string hash ? hash : LedgerChainHasher.GenesisPreviousHash;
	}

	private static void AddSubjectParameters(SqliteCommand command, SubjectPredicate predicate)
	{
		foreach (SqliteParameter parameter in predicate.Parameters)
		{
			command.Parameters.Add(new SqliteParameter(parameter.ParameterName, parameter.Value));
		}
	}

	/// <summary>Assigns a composed statement. Every fragment is a compile-time constant, an internal table
	/// or column name from <see cref="Targets"/>, or a parameter name - no operator-supplied text reaches
	/// SQL; the subject is always bound as a parameter.</summary>
	private static void SetCommandText(SqliteCommand command, string sql)
	{
#pragma warning disable CA2100 // Reviewed: composed from constant fragments and internal schema names; the subject is bound, never interpolated.
		command.CommandText = sql;
#pragma warning restore CA2100
	}

	/// <summary>Reports the frozen counts for a refused apply, so a legal hold is visible as a number rather
	/// than as a bare "no".</summary>
	private async Task PopulateCountsAsync(
		PurgeBySubjectReportDto report,
		SubjectMatch match,
		CancellationToken cancellationToken)
	{
		long total = 0;
		await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
		await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
		SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();
		foreach (SubjectTarget target in Targets)
		{
			PurgeBySubjectTableDto row = new() { Table = target.Table };
			SubjectPredicate predicate = BuildPredicate(match, target);
			if (predicate.IsApplicable)
			{
				row.RowsMatched = await CountAsync(connection, target, predicate, cancellationToken).ConfigureAwait(false);
				total += row.RowsMatched;
			}

			report.Tables.Add(row);
		}

		report.Tables.Sort(static (left, right) => string.CompareOrdinal(left.Table, right.Table));
		report.TotalRowsMatched = total;
	}
}
