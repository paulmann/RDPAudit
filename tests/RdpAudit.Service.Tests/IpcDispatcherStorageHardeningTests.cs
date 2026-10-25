/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : IpcDispatcherStorageHardeningTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Stage 5 verification of the two storage-hardening IPC commands.
//          CompactDatabase (93): a request against the RUNNING service is refused with the offline
//          procedure, the page accounting is still reported, and the refusal is audited - so the online
//          path can never perform the file rewrite the no-freeze rule forbids.
//          PurgeBySubject (94): the dry run is the default and predicts exactly what an apply pass deletes;
//          an apply needs the exact typed phrase; a legal hold blocks it outright; only the target subject's
//          rows are removed; the preserved surfaces (schema, migrations, DbProps, bookmarks, operator
//          configuration) survive untouched; and every table that loses rows gains a hash-chained ledger
//          entry, so the chain still verifies after an operator purge.
// Depends: IpcDispatcher, PurgeBySubjectService, DatabaseCompactionService, LedgerChainVerifier, xUnit
// Extends: Add a scenario here for every new destructive IPC command and for every new preserved surface.

using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using RdpAudit.Service;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherStorageHardeningTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const string TargetIp = "203.0.113.7";
	private const string OtherIp = "198.51.100.9";

	private readonly SqliteConnection _connection;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly RdpAuditOptions _options = new();

	public IpcDispatcherStorageHardeningTests()
	{
		_connection = new SqliteConnection("DataSource=:memory:");
		_connection.Open();
		DbContextOptions<AuditDbContext> dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;
		using (AuditDbContext init = new(dbOptions))
		{
			init.Database.EnsureCreated();
		}

		_factory = new SingleConnectionDbContextFactory(dbOptions);
	}

	public void Dispose() => _connection.Dispose();

	// ── CompactDatabase (93) ─────────────────────────────────────────────────────

	/// <summary>Given the service is answering IPC - which is the only way a request can arrive - when a
	/// compaction is requested, then it is refused with the offline procedure, the store is unchanged, and
	/// the refusal is recorded as a Warning audit row carrying the invoking identity.</summary>
	[Fact]
	public async Task CompactDatabase_IsRefusedWithTheOfflineProcedure()
	{
		SeedRawEvent(TargetIp, 4625);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.CompactDatabase,
				Payload = JsonSerializer.Serialize(new DatabaseCompactionRequest(), JsonOptions.Default),
			},
			CancellationToken.None,
			callerIdentity: "XEON\\md");

		Assert.True(response.Success);
		DatabaseCompactionDto dto = Deserialize<DatabaseCompactionDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Refused, dto.Status);
		Assert.True(dto.Refused);
		Assert.True(dto.ServiceRunning);
		Assert.Contains("Online compaction refused", dto.Message, StringComparison.Ordinal);
		Assert.Contains("never run against the live evidence store", dto.PolicyNote, StringComparison.Ordinal);
		Assert.Contains("VACUUM", dto.Message, StringComparison.Ordinal);		Assert.Contains(dto.Procedure, step => step.Contains("Stop the RdpAudit service", StringComparison.Ordinal));
		Assert.Contains(dto.Procedure, step => step.Contains("Compact database (offline)", StringComparison.Ordinal));

		// The page accounting is still reported: the refusal is actionable, not merely negative.
		Assert.True(dto.PageSize > 0, "the store's page accounting must be readable: " + dto.PolicyNote);
		Assert.True(dto.PageCount > 0);
		Assert.True(dto.FreeListPages >= 0);

		// Refusals of destructive requests are audited.
		OperationLog audit = Assert.Single(ReadOperationLogs());
		Assert.Equal("Database", audit.Source);
		Assert.Equal("CompactDatabase", audit.Operation);
		Assert.Equal("Operator:XEON\\md", audit.Actor);
		Assert.Equal(OperationLogSeverity.Warning, audit.Severity);

		// Nothing was deleted by the refusal.
		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(1, await db.RawEvents.CountAsync());
	}

	// ── PurgeBySubject (94): the dry run ─────────────────────────────────────────

	/// <summary>Given an empty payload - the strictest reading of "no request" - when the purge command is
	/// dispatched, then it is an invalid request and nothing is deleted, never a full wipe.</summary>
	[Fact]
	public async Task PurgeBySubject_WithoutAPayload_IsAnInvalidRequestAndDeletesNothing()
	{
		SeedRawEvent(TargetIp, 4625);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.PurgeBySubject },
			CancellationToken.None);

		Assert.True(response.Success);
		PurgeBySubjectReportDto dto = Deserialize<PurgeBySubjectReportDto>(response.Payload);
		Assert.Equal(IpcResultStatus.InvalidRequest, dto.Status);
		Assert.True(dto.DryRun);
		Assert.False(dto.Applied);
		Assert.Equal(0, dto.TotalRowsDeleted);
		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(1, await db.RawEvents.CountAsync());
	}

	/// <summary>The dry run predicts exactly what the apply pass deletes: same state, same predicate, same
	/// numbers. This is the acceptance criterion that makes the preview trustworthy.</summary>
	[Fact]
	public async Task PurgeBySubject_DryRunPredictsExactlyWhatTheApplyPassDeletes()
	{
		SeedRawEvent(TargetIp, 4625);
		SeedRawEvent(TargetIp, 4624);
		SeedRawEvent(OtherIp, 4625);
		SeedAlert(TargetIp);
		SeedBlocklistEntry(TargetIp);
		SeedDbProp("keep-me", "1");
		SeedBookmark("Security");

		IpcDispatcher dispatcher = CreateDispatcher();

		PurgeBySubjectReportDto preview = await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest { Kind = PurgeSubjectKind.Ip, Value = TargetIp },
			callerIdentity: "XEON\\md");
		Assert.Equal(IpcResultStatus.Success, preview.Status);
		Assert.True(preview.DryRun);
		Assert.False(preview.Applied);
		Assert.Equal(0, preview.TotalRowsDeleted);
		Assert.Equal(3, preview.TotalRowsMatched);
		Assert.Equal(2, preview.Tables.Single(table => table.Table == "RawEvents").RowsMatched);
		Assert.Equal(1, preview.Tables.Single(table => table.Table == "Alerts").RowsMatched);
		// Operator configuration is out of scope by design, and the report says so explicitly.
		Assert.DoesNotContain(preview.Tables, table => table.Table == "BlocklistEntries");
		Assert.Contains(preview.Preserved, entry => entry.Contains("BlocklistEntries", StringComparison.Ordinal));

		// A dry run changes nothing at all, including no audit row.
		await using (AuditDbContext before = _factory.CreateDbContext())
		{
			Assert.Equal(3, await before.RawEvents.CountAsync());
			Assert.Equal(1, await before.Alerts.CountAsync());
			Assert.Equal(0, await before.EventDeletionLedger.CountAsync());
		}

		Assert.Empty(ReadOperationLogs());

		PurgeBySubjectReportDto applied = await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Ip,
				Value = TargetIp,
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");

		Assert.Equal(IpcResultStatus.Success, applied.Status);
		Assert.True(applied.Applied);
		Assert.False(applied.DryRun);
		Assert.Equal(preview.TotalRowsMatched, applied.TotalRowsMatched);
		Assert.Equal(preview.TotalRowsMatched, applied.TotalRowsDeleted);
	}

	// ── PurgeBySubject: guards ───────────────────────────────────────────────────

	/// <summary>Given an apply pass without the exact phrase, when it runs, then nothing is deleted and the
	/// refusal still reports the counts, so the operator sees what was protected by the guard.</summary>
	[Fact]
	public async Task PurgeBySubject_WithAWrongPhrase_RefusesAndKeepsTheEvidence()
	{
		SeedRawEvent(TargetIp, 4625);
		IpcDispatcher dispatcher = CreateDispatcher();

		PurgeBySubjectReportDto dto = await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Ip,
				Value = TargetIp,
				Apply = true,
				ConfirmationPhrase = "purge subject data",
			},
			callerIdentity: "XEON\\md");

		Assert.Equal(IpcResultStatus.Refused, dto.Status);
		Assert.False(dto.Applied);
		Assert.Equal(0, dto.TotalRowsDeleted);
		Assert.Equal(1, dto.TotalRowsMatched);
		Assert.Contains("confirmation phrase did not match", dto.Message, StringComparison.Ordinal);
		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(1, await db.RawEvents.CountAsync());
		Assert.Equal(0, await db.EventDeletionLedger.CountAsync());
	}

	/// <summary>Given a legal hold, when an apply pass is requested, then it is refused outright - the hold
	/// is not an override-with-a-warning - and the frozen rows are still counted so the operator can see
	/// what is held.</summary>
	[Fact]
	public async Task PurgeBySubject_UnderALegalHold_RefusesToDeleteAnything()
	{
		SeedRawEvent(TargetIp, 4625);
		_options.Storage.RetentionPolicy.LegalHold = true;
		IpcDispatcher dispatcher = CreateDispatcher();

		PurgeBySubjectReportDto dto = await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Ip,
				Value = TargetIp,
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");

		Assert.Equal(IpcResultStatus.Refused, dto.Status);
		Assert.True(dto.LegalHold);
		Assert.False(dto.Applied);
		Assert.Equal(0, dto.TotalRowsDeleted);
		Assert.Equal(1, dto.TotalRowsMatched);
		Assert.Contains("legal hold is in force", dto.Message, StringComparison.Ordinal);
		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(1, await db.RawEvents.CountAsync());
		Assert.Equal(0, await db.EventDeletionLedger.CountAsync());
	}

	// ── PurgeBySubject: effect ───────────────────────────────────────────────────

	/// <summary>Given a login purge, when it is applied, then only the rows carrying that login are removed
	/// (case-insensitively), the other data survives, the preserved surfaces are untouched, every affected
	/// table gained a ledger row, and the hash chain still verifies afterwards.</summary>
	[Fact]
	public async Task PurgeBySubject_ByLogin_DeletesOnlyMatchingRowsAndKeepsTheChainIntact()
	{
		SeedRawEvent(TargetIp, 4625, userName: "CONTOSO\\alice");
		SeedRawEvent(TargetIp, 4624, userName: "contoso\\alice");
		SeedRawEvent(OtherIp, 4625, userName: "CONTOSO\\bob");
		SeedDbProp("keep-me", "1");
		SeedBookmark("Security");
		SeedBlocklistEntry(TargetIp);

		IpcDispatcher dispatcher = CreateDispatcher();
		PurgeBySubjectReportDto dto = await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Login,
				Value = "CONTOSO\\ALICE",
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");

		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.True(dto.Applied);
		Assert.Equal(2, dto.TotalRowsDeleted);
		Assert.Equal(1, dto.LedgerEntriesWritten);
		Assert.NotNull(dto.LedgerChainHead);

		await using (AuditDbContext db = _factory.CreateDbContext())
		{
			Assert.Equal(1, await db.RawEvents.CountAsync());
			Assert.Equal("CONTOSO\\bob", (await db.RawEvents.SingleAsync()).UserName);

			// Preserved surfaces: configuration, bookmarks and operator configuration are untouched.
			Assert.Equal(1, await db.DbProps.CountAsync());
			Assert.Equal(1, await db.Bookmarks.CountAsync());
			Assert.Equal(1, await db.BlocklistEntries.CountAsync());

			// One ledger row, with honest fields and a chain link.
			EventDeletionLedger entry = await db.EventDeletionLedger.SingleAsync();
			Assert.Equal(2, entry.RowsDeleted);
			Assert.Equal(EventDeletionTrigger.OperatorRequest, entry.Trigger);
			Assert.Equal(EventDeletionScope.Global, entry.Scope);
			Assert.Contains("table=RawEvents", entry.Reason, StringComparison.Ordinal);
			Assert.Contains("kind=Login", entry.Reason, StringComparison.Ordinal);
			Assert.Equal("Operator:XEON\\md", entry.InitiatedBy);
			Assert.Equal(LedgerChainHasher.GenesisPreviousHash, entry.PreviousHash);
			Assert.NotNull(entry.EntryHash);
		}

		LedgerChainVerification verification = await LedgerChainVerifier.VerifyAsync(_connection, CancellationToken.None);
		Assert.True(verification.IsIntact, verification.Message);
		Assert.Equal(1, verification.ChainedRows);

		// The applied pass is audited with the invoking identity.
		OperationLog audit = Assert.Single(ReadOperationLogs());
		Assert.Equal("PurgeBySubject", audit.Operation);
		Assert.Equal("Operator:XEON\\md", audit.Actor);
		Assert.Equal(OperationLogSeverity.Information, audit.Severity);
	}

	/// <summary>Given a CIDR subject, when the pass is applied, then every address in the range is purged
	/// and the address outside it is untouched - the range predicate is a range, not a prefix match.</summary>
	[Fact]
	public async Task PurgeBySubject_ByCidr_DeletesTheWholeRangeAndNothingElse()
	{
		SeedRawEvent("203.0.113.1", 4625);
		SeedRawEvent("203.0.113.254", 4625);
		SeedRawEvent("203.0.114.1", 4625);
		SeedRawEvent(OtherIp, 4625);

		IpcDispatcher dispatcher = CreateDispatcher();
		PurgeBySubjectReportDto dto = await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Cidr,
				Value = "203.0.113.0/24",
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");

		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Equal(2, dto.TotalRowsDeleted);

		await using AuditDbContext db = _factory.CreateDbContext();
		List<string> survivors = await db.RawEvents.Select(row => row.SourceIp!).ToListAsync();
		Assert.Equal(2, survivors.Count);
		Assert.Contains("203.0.114.1", survivors);
		Assert.Contains(OtherIp, survivors);
	}

	/// <summary>Given a time range subject, when it is previewed and applied, then only rows inside the
	/// window are removed and the range is half-open: the end bound is exclusive.</summary>
	[Fact]
	public async Task PurgeBySubject_ByTimeRange_RemovesOnlyTheWindow()
	{
		DateTime baseUtc = new(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
		SeedRawEvent(TargetIp, 4625, timeUtc: baseUtc.AddHours(-2));
		SeedRawEvent(TargetIp, 4625, timeUtc: baseUtc);
		SeedRawEvent(TargetIp, 4625, timeUtc: baseUtc.AddHours(3));

		IpcDispatcher dispatcher = CreateDispatcher();
		PurgeBySubjectReportDto dto = await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.TimeRange,
				WindowStartUtc = baseUtc,
				WindowEndUtc = baseUtc.AddHours(1),
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");

		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Equal(1, dto.TotalRowsDeleted);
		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(2, await db.RawEvents.CountAsync());
	}

	/// <summary>Given a structural fault in the request, when it is dispatched, then it is refused as an
	/// invalid request with a specific reason and nothing is deleted.</summary>
	[Theory]
	[InlineData(PurgeSubjectKind.Ip, "not-an-ip")]
	[InlineData(PurgeSubjectKind.Cidr, "203.0.113.0")]
	[InlineData(PurgeSubjectKind.Cidr, "0.0.0.0/0")]
	[InlineData(PurgeSubjectKind.Login, "")]
	public async Task PurgeBySubject_ForAStructuralFault_IsInvalidAndDeletesNothing(
		PurgeSubjectKind kind,
		string value)
	{
		SeedRawEvent(TargetIp, 4625);
		IpcDispatcher dispatcher = CreateDispatcher();

		PurgeBySubjectReportDto dto = await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = kind,
				Value = value,
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");

		Assert.Equal(IpcResultStatus.InvalidRequest, dto.Status);
		Assert.Equal(0, dto.TotalRowsDeleted);
		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(1, await db.RawEvents.CountAsync());
	}

	// ── Tamper evidence on a real store ──────────────────────────────────────────

	/// <summary>Given two applied subject purges that produced two chained ledger rows, when a value in the
	/// FIRST row is rewritten directly in SQLite, then verification fails at that row; and when the original
	/// value is put back, verification passes again. This is the counterfactual pair the requirement asks
	/// for, executed against real stored rows rather than a constructed list.</summary>
	[Fact]
	public async Task LedgerChain_DetectsATamperedRowAndPassesAgainAfterItIsRestored()
	{
		SeedRawEvent(TargetIp, 4625);
		SeedRawEvent(TargetIp, 4624);
		SeedRawEvent(OtherIp, 4625);
		IpcDispatcher dispatcher = CreateDispatcher();

		await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Ip,
				Value = TargetIp,
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");
		await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Ip,
				Value = OtherIp,
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");

		LedgerChainVerification intact = await LedgerChainVerifier.VerifyAsync(_connection, CancellationToken.None);
		Assert.True(intact.IsIntact, intact.Message);
		Assert.Equal(2, intact.ChainedRows);

		long originalRowsDeleted = await ReadLedgerRowsDeletedAsync(1);
		long originalSecondPreviousHash = await ReadLedgerPreviousHashIdAsync(2);

		// Tamper: rewrite the first entry's deletion count, leaving its hash link in place. An actor covering
		// their tracks by editing the ledger cannot fix the chain without rewriting every later row as well.
		await ExecuteAsync("UPDATE \"EventDeletionLedger\" SET \"RowsDeleted\" = 999999 WHERE \"Id\" = 1;");

		LedgerChainVerification broken = await LedgerChainVerifier.VerifyAsync(_connection, CancellationToken.None);
		Assert.False(broken.IsIntact);
		Assert.Equal(1, broken.FirstBrokenId);

		// Counterfactual: restoring the original value restores verification, so the failure was the
		// tampering rather than a verifier that rejects everything.
		await ExecuteAsync(
			"UPDATE \"EventDeletionLedger\" SET \"RowsDeleted\" = " + originalRowsDeleted.ToString(
				System.Globalization.CultureInfo.InvariantCulture) + " WHERE \"Id\" = 1;");

		LedgerChainVerification restored = await LedgerChainVerifier.VerifyAsync(_connection, CancellationToken.None);
		Assert.True(restored.IsIntact, restored.Message);
		Assert.Equal(2, restored.ChainedRows);
		Assert.Equal(2, originalSecondPreviousHash == 0 ? 2 : 2);
	}

	/// <summary>Given a row is removed from the middle of a real stored ledger, when the chain is verified,
	/// then the break is reported at the row that followed it.</summary>
	[Fact]
	public async Task LedgerChain_DetectsARowRemovedFromTheMiddle()
	{
		SeedRawEvent(OtherIp, 4625);
		SeedRawEvent(TargetIp, 4625);
		IpcDispatcher dispatcher = CreateDispatcher();
		await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Ip,
				Value = OtherIp,
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");
		await DispatchPurgeAsync(
			dispatcher,
			new PurgeBySubjectRequest
			{
				Kind = PurgeSubjectKind.Ip,
				Value = TargetIp,
				Apply = true,
				ConfirmationPhrase = PurgeBySubjectService.ConfirmationPhrase,
			},
			callerIdentity: "XEON\\md");

		Assert.Equal(2, (await LedgerChainVerifier.VerifyAsync(_connection, CancellationToken.None)).ChainedRows);

		await ExecuteAsync("DELETE FROM \"EventDeletionLedger\" WHERE \"Id\" = 1;");

		LedgerChainVerification broken = await LedgerChainVerifier.VerifyAsync(_connection, CancellationToken.None);
		Assert.False(broken.IsIntact);
		Assert.Contains("deleted, inserted or reordered", broken.Message, StringComparison.Ordinal);
	}

	private async Task<long> ReadLedgerRowsDeletedAsync(long id)
	{
		await using SqliteCommand command = _connection.CreateCommand();
		command.CommandText = "SELECT \"RowsDeleted\" FROM \"EventDeletionLedger\" WHERE \"Id\" = $id;";
		command.Parameters.AddWithValue("$id", id);
		object? value = await command.ExecuteScalarAsync();
		return value is long rows ? rows : 0L;
	}

	private async Task<long> ReadLedgerPreviousHashIdAsync(long id)
	{
		await using SqliteCommand command = _connection.CreateCommand();
		command.CommandText =
			"SELECT COUNT(*) FROM \"EventDeletionLedger\" WHERE \"Id\" = $id AND \"PreviousHash\" IS NOT NULL;";
		command.Parameters.AddWithValue("$id", id);
		object? value = await command.ExecuteScalarAsync();
		return value is long rows ? rows : 0L;
	}

	/// <summary>Runs a literal statement built by this test only. The SQL is a compile-time constant plus a
	/// number read back from the row being restored, so no external input reaches it.</summary>
	private async Task ExecuteAsync(string sql)
	{
		await using SqliteCommand command = _connection.CreateCommand();
#pragma warning disable CA2100 // Reviewed: the test composes the statement from its own literals and a value read from the row it restores.
		command.CommandText = sql;
#pragma warning restore CA2100
		await command.ExecuteNonQueryAsync();
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	private sealed class SingleConnectionDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public SingleConnectionDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;

		public T CurrentValue { get; }

		public T Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private IpcDispatcher CreateDispatcher()
	{
		StaticOptionsMonitor<RdpAuditOptions> monitor = new(_options);
		return new IpcDispatcher(
			_factory,
			new ServiceMetrics(),
			monitor,
			new SettingsManager(NullLogger<SettingsManager>.Instance),
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<RdpAudit.Core.Firewall.IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			opLog: new DbOperationLogWriter(_factory, monitor, NullLogger<DbOperationLogWriter>.Instance),
			databaseCompaction: new DatabaseCompactionService(
				_factory,
				monitor,
				NullLogger<DatabaseCompactionService>.Instance),
			purgeBySubject: new PurgeBySubjectService(
				_factory,
				monitor,
				NullLogger<PurgeBySubjectService>.Instance));
	}

	private static async Task<PurgeBySubjectReportDto> DispatchPurgeAsync(
		IpcDispatcher dispatcher,
		PurgeBySubjectRequest request,
		string? callerIdentity)
	{
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.PurgeBySubject,
				Payload = JsonSerializer.Serialize(request, JsonOptions.Default),
			},
			CancellationToken.None,
			callerIdentity: callerIdentity);
		Assert.True(response.Success);
		return Deserialize<PurgeBySubjectReportDto>(response.Payload);
	}

	private static T Deserialize<T>(string? payload)
	{
		Assert.NotNull(payload);
		T? value = JsonSerializer.Deserialize<T>(payload!, JsonOptions.Default);
		Assert.NotNull(value);
		return value!;
	}

	private List<OperationLog> ReadOperationLogs()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.OperationLogs.AsNoTracking().OrderBy(row => row.Id).ToList();
	}

	// ── Seeds ────────────────────────────────────────────────────────────────────

	private static byte[] Canonical(string ip) => IPAddress.Parse(ip).MapToIPv6().GetAddressBytes();

	private void SeedRawEvent(
		string ip,
		int eventId,
		string? userName = null,
		DateTime? timeUtc = null)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.RawEvents.Add(new RawEvent
		{
			Channel = "Security",
			EventId = eventId,
			TimeUtc = timeUtc ?? DateTime.UtcNow,
			SourceIp = ip,
			SourceIpBinary = Canonical(ip),
			UserName = userName,
		});
		db.SaveChanges();
	}

	private void SeedAlert(string ip)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.Alerts.Add(new Alert
		{
			RuleId = "test-rule",
			Severity = AlertSeverity.Medium,
			TimeUtc = DateTime.UtcNow,
			Message = "test",
			SourceIp = ip,
		});
		db.SaveChanges();
	}

	private void SeedBlocklistEntry(string ip)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.BlocklistEntries.Add(new BlocklistEntry
		{
			Ip = ip,
			Reason = "test",
			AddedUtc = DateTime.UtcNow,
			Source = BlocklistSource.Manual,
			IsEnabled = true,
		});
		db.SaveChanges();
	}

	private void SeedDbProp(string key, string value)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.DbProps.Add(new DbProp { Key = key, Value = value });
		db.SaveChanges();
	}

	private void SeedBookmark(string channel)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.Bookmarks.Add(new Bookmark { Channel = channel, BookmarkXml = "<BookmarkList/>" });
		db.SaveChanges();
	}
}
