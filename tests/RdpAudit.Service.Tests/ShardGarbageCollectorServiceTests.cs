/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardGarbageCollectorServiceTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Verifies orphan-shard collection against a real filesystem, a real IpEventSummary and the
//          real inventory service: a dry run deletes nothing, an apply pass removes only shards that no
//          summary row names and that are past the configured grace period, a shard a live writer holds
//          open is never touched, a referenced shard is not even a candidate, and every deletion is
//          named in the report and audited with its own OperationLog row.
// Depends: ShardGarbageCollectorService, ShardInventoryService, ShardWriter, AuditDbContext
// Extends: Add a case here for every new deletion guard; never assert a deletion the pass could not
//          prove.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Service.Services;
using RdpAudit.Service.Storage;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class ShardGarbageCollectorServiceTests : IDisposable
{
	private readonly string _directory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
	private readonly SqliteConnection _connection = new("DataSource=:memory:");
	private readonly SqliteConnection _auditConnection = new("DataSource=:memory:");
	private readonly RecordingOperationLogWriter _audit = new();
	private readonly string _actionsRoot;

	public ShardGarbageCollectorServiceTests()
	{
		Directory.CreateDirectory(_directory);
		_actionsRoot = Path.Combine(_directory, ShardPath.ActionsRootFolder);
		Directory.CreateDirectory(_actionsRoot);

		_connection.Open();
		_auditConnection.Open();
		foreach (SqliteConnection connection in new[] { _connection, _auditConnection })
		{
			DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(connection).Options;
			using AuditDbContext context = new(options);
			context.Database.EnsureCreated();
		}
	}

	public void Dispose()
	{
		_connection.Dispose();
		_auditConnection.Dispose();
		SqliteConnection.ClearAllPools();
		try { Directory.Delete(_directory, recursive: true); }
		catch (IOException) { }
		catch (UnauthorizedAccessException) { }
	}

	// ── Dry run ─────────────────────────────────────────────────────────────────

	/// <summary>Given an orphan past the grace period, when the collector dry-runs, then the candidate is
	/// listed as eligible and NOTHING is deleted.</summary>
	[Fact]
	public async Task DryRun_ListsTheCandidateAndDeletesNothing()
	{
		string orphan = CreateShardFile("203.0.113.10", records: 3, ageDays: 40);
		ShardGarbageCollectionReportDto report = await CollectAsync(dryRun: true);

		ShardGarbageCandidateDto candidate = Assert.Single(report.Candidates);
		Assert.Equal(ShardGarbageDisposition.Eligible, candidate.Disposition);
		Assert.Equal(3, candidate.Records);
		Assert.True(candidate.Bytes > 0);
		Assert.NotNull(candidate.LastWriteUtc);
		Assert.True(candidate.AgeDays > 39);
		Assert.Equal(0, report.DeletedFileCount);
		Assert.Empty(report.DeletedPaths);
		Assert.True(report.DryRun);
		Assert.True(File.Exists(orphan));
		Assert.Empty(_audit.Entries);
		Assert.Contains("dry run", report.Message ?? string.Empty, StringComparison.OrdinalIgnoreCase);
	}

	// ── Apply ───────────────────────────────────────────────────────────────────

	/// <summary>Given one orphan past the grace period and one inside it, when the collection is applied,
	/// then only the old orphan is removed, the young one is reported as kept with its reason, and the
	/// report's byte and record totals describe only what was actually deleted.</summary>
	[Fact]
	public async Task Apply_RemovesOnlyOrphansPastTheGracePeriod()
	{
		string oldOrphan = CreateShardFile("203.0.113.20", records: 4, ageDays: 30);
		string youngOrphan = CreateShardFile("203.0.113.21", records: 2, ageDays: 1);

		ShardGarbageCollectionReportDto report = await CollectAsync(dryRun: false, graceDays: 14);

		Assert.False(File.Exists(oldOrphan));
		Assert.True(File.Exists(youngOrphan));
		Assert.Equal(1, report.DeletedFileCount);
		Assert.Single(report.DeletedPaths);
		Assert.Equal(4, report.DeletedRecords);
		Assert.True(report.DeletedBytes >= ShardingOptions.ExpectedShardFileBytes(4));

		ShardGarbageCandidateDto kept = report.Candidates.Single(candidate =>
			candidate.RelativePath.EndsWith("cb007115" + ShardPath.ShardExtension, StringComparison.Ordinal));
		Assert.Equal(ShardGarbageDisposition.YoungerThanGracePeriod, kept.Disposition);
		Assert.Equal(14, report.OrphanGraceDays);

		OperationLogEntry audit = Assert.Single(_audit.Entries);
		Assert.Equal(ShardGarbageCollectorService.OperationLogSource, audit.Source);
		Assert.Equal(ShardGarbageCollectorService.OperationLogOperation, audit.Operation);
		Assert.Equal("Operator:TEST\\operator", audit.Actor);
		Assert.Contains(report.DeletedPaths[0], audit.Message, StringComparison.Ordinal);
		Assert.NotNull(audit.DetailsJson);
		Assert.Contains("records=4", audit.Message, StringComparison.Ordinal);
		Assert.Contains("ageDays=", audit.Message, StringComparison.Ordinal);
	}

	/// <summary>Given the grace period is configured to one day, when a two-day-old orphan is collected,
	/// then it is eligible: the period comes from the live policy, not from a constant.</summary>
	[Fact]
	public async Task Apply_UsesTheConfiguredGracePeriod()
	{
		string orphan = CreateShardFile("203.0.113.30", records: 1, ageDays: 2);

		ShardGarbageCollectionReportDto dryRun = await CollectAsync(dryRun: true, graceDays: 30);
		Assert.Equal(ShardGarbageDisposition.YoungerThanGracePeriod, Assert.Single(dryRun.Candidates).Disposition);

		ShardGarbageCollectionReportDto applied = await CollectAsync(dryRun: false, graceDays: 1);
		Assert.Equal(1, applied.DeletedFileCount);
		Assert.False(File.Exists(orphan));
	}

	// ── Live evidence is never touched ──────────────────────────────────────────

	/// <summary>Given an IpEventSummary row names a shard, when the collection runs, then that file is
	/// not even a candidate: live evidence is not offered for deletion, let alone deleted.</summary>
	[Fact]
	public async Task ReferencedShard_IsNeverACandidate()
	{
		AddIpEventSummary("203.0.113.40", "actions/cb/00/cb007128" + ShardPath.ShardExtension);
		string referenced = CreateShardFile("203.0.113.40", records: 5, ageDays: 365, reuseExistingPath: true);

		ShardGarbageCollectionReportDto report = await CollectAsync(dryRun: false);

		Assert.Empty(report.Candidates);
		Assert.Equal(0, report.DeletedFileCount);
		Assert.True(File.Exists(referenced));
		Assert.Empty(_audit.Entries);
	}

	/// <summary>Given a live shard writer holds an orphan shard open, when the collection runs, then the
	/// file is reported as open in a writer and is kept: the collector never pulls a shard out from under
	/// the writer that is mapping it.</summary>
	[Fact]
	public async Task OpenShardInTheWriterPool_IsKept()
	{
		using ShardIngestionSink sink = CreateSink();
		RawEvent rawEvent = CreateEvent("203.0.113.50", 1);
		sink.Append(rawEvent);
		string openShard = Assert.Single(Directory.EnumerateFiles(_actionsRoot, "*" + ShardPath.ShardExtension, SearchOption.AllDirectories));
		File.SetLastWriteTimeUtc(openShard, DateTime.UtcNow.AddDays(-30));

		ShardGarbageCollectionReportDto report = await CollectAsync(dryRun: false, sink: sink);

		ShardGarbageCandidateDto candidate = Assert.Single(report.Candidates);
		Assert.Equal(ShardGarbageDisposition.OpenInWriter, candidate.Disposition);
		Assert.Equal(0, report.DeletedFileCount);
		Assert.True(File.Exists(openShard));
		Assert.Empty(_audit.Entries);
	}

	// ── Honest degradation ──────────────────────────────────────────────────────

	/// <summary>Given there is no shard tree at all, when the collection runs, then it reports that there
	/// was nothing to examine instead of reporting a successful zero-file collection.</summary>
	[Fact]
	public async Task MissingShardTree_IsReportedAsNothingToExamine()
	{
		Directory.Delete(_actionsRoot, recursive: true);

		ShardGarbageCollectionReportDto report = await CollectAsync(dryRun: false);

		Assert.Equal(IpcResultStatus.Unavailable, report.Status);
		Assert.Contains("no shard tree", report.Message ?? string.Empty, StringComparison.OrdinalIgnoreCase);
		Assert.Empty(_audit.Entries);
	}

	/// <summary>Given the audit writer throws, when a deletion succeeds, then the report says the files
	/// were deleted but not fully accounted for - it never claims a clean audited pass.</summary>
	[Fact]
	public async Task AuditFailure_IsReportedInsteadOfClaimingACleanPass()
	{
		_audit.ThrowOnWrite = true;
		string orphan = CreateShardFile("203.0.113.60", records: 1, ageDays: 40);

		ShardGarbageCollectionReportDto report = await CollectAsync(dryRun: false);

		Assert.False(File.Exists(orphan));
		Assert.Equal(1, report.DeletedFileCount);
		Assert.Equal(IpcResultStatus.Unavailable, report.Status);
		Assert.Contains("audit entry could not be written", report.Message ?? string.Empty, StringComparison.OrdinalIgnoreCase);
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	private async Task<ShardGarbageCollectionReportDto> CollectAsync(
		bool dryRun,
		int graceDays = 14,
		ShardIngestionSink? sink = null)
	{
		ShardingOptions sharding = new()
		{
			Enabled = true,
			ActionsRoot = _actionsRoot,
			OrphanGraceDays = graceDays,
		};
		RdpAuditOptions options = new() { Sharding = sharding };
		StaticOptionsMonitor<RdpAuditOptions> monitor = new(options);
		ShardInventoryService inventory = new(
			new SingleConnectionDbContextFactory(_connection),
			monitor,
			NullLogger<ShardInventoryService>.Instance,
			sink,
			settings: null);
		ShardGarbageCollectorService collector = new(
			inventory,
			monitor,
			NullLogger<ShardGarbageCollectorService>.Instance,
			sink,
			_audit);

		return await collector.CollectAsync(
			new CollectShardGarbageRequest { DryRun = dryRun },
			"Operator:TEST\\operator",
			CancellationToken.None);
	}

	private ShardIngestionSink CreateSink()
	{
		RdpAuditOptions options = new()
		{
			Sharding = new ShardingOptions { Enabled = true, ActionsRoot = _actionsRoot, ShardCapacityRecords = 4 },
		};
		return new ShardIngestionSink(
			new StaticOptionsMonitor<RdpAuditOptions>(options),
			NullLogger<ShardIngestionSink>.Instance,
			new ServiceMetrics());
	}

	/// <summary>Writes a real shard file at the canonical path for <paramref name="ip"/> with the
	/// requested number of records, then ages it.</summary>
	private string CreateShardFile(string ip, uint records, double ageDays, bool reuseExistingPath = false)
	{
		char[] relative = new char[64];
		Assert.True(ShardPath.TryComposeShardPath(System.Net.IPAddress.Parse(ip), relative, out int length));
		string relativePath = new(relative, 0, length);
		string absolute = Path.Combine(
			_directory,
			relativePath.Replace('/', Path.DirectorySeparatorChar));
		Directory.CreateDirectory(Path.GetDirectoryName(absolute)!);

		if (!reuseExistingPath || !File.Exists(absolute))
		{
			using ShardWriter writer = ShardWriter.OpenOrCreate(absolute, capacity: 8);
			for (uint index = 0; index < records; index++)
			{
				ShardRecord record = ShardRecord.Create(
					index, DateTime.UtcNow.AddMinutes(-index).Ticks, 4625, (ushort)ChannelCode.Security, 1,
					255, 10, 0, 0, 1, 1, -1, -1, -1, -1, -1, 0);
				writer.Append(in record, out _);
			}
			writer.Commit();
		}

		File.SetLastWriteTimeUtc(absolute, DateTime.UtcNow.AddDays(-ageDays));
		return absolute;
	}

	private void AddIpEventSummary(string ip, string shardRelativePath)
	{
		System.Net.IPAddress parsed = System.Net.IPAddress.Parse(ip);
		byte[] binary = parsed.MapToIPv6().GetAddressBytes();
		using SqliteCommand command = _connection.CreateCommand();
		command.CommandText = """
INSERT INTO IpEventSummary (IpBinary16, IpText, AddressFamily, FirstEventUtc, FirstEventId, FirstEventSequence,
	FirstEventSnapshot, LastEventUtc, LastEventId, LastEventSequence, LastEventSnapshot, TotalEventCount,
	SuccessCount, FailureCount, ShardRelativePath, IsSubnetAggregate, Flags)
VALUES ($ip, $text, 4, 0, 0, 0, X'', 0, 0, 0, X'', 1, 0, 1, $path, 0, 0);
""";
		command.Parameters.AddWithValue("$ip", binary);
		command.Parameters.AddWithValue("$text", parsed.MapToIPv6().ToString());
		command.Parameters.AddWithValue("$path", shardRelativePath);
		command.ExecuteNonQuery();
	}

	private static RawEvent CreateEvent(string ip, long sequence) => new()
	{
		EventId = 4625,
		Channel = "Security",
		TimeUtc = new DateTime(2026, 8, 14, 1, 0, 0, DateTimeKind.Utc).AddSeconds(sequence),
		IngestionSequence = sequence,
		SourceIp = ip,
		Status = "0xC000006D",
		LogonType = 10,
	};

	private sealed class SingleConnectionDbContextFactory(SqliteConnection connection) : IDbContextFactory<AuditDbContext>
	{
		public AuditDbContext CreateDbContext()
		{
			DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
				.UseSqlite(connection)
				.Options;
			return new AuditDbContext(options);
		}
	}

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
		where T : class
	{
		public T CurrentValue => value;
		public T Get(string? name) => value;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class RecordingOperationLogWriter : IOperationLogWriter
	{
		public List<OperationLogEntry> Entries { get; } = new();

		public bool ThrowOnWrite { get; set; }

		public bool IsDebugEnabled => false;

		public Task WriteAsync(OperationLogEntry entry, CancellationToken ct = default)
		{
			if (ThrowOnWrite)
			{
				throw new InvalidOperationException("The audit store is unavailable.");
			}

			Entries.Add(entry);
			return Task.CompletedTask;
		}

		public Task InfoAsync(string source, string operation, string message, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = OperationLogSeverity.Information, Source = source, Operation = operation, Message = message }, ct);

		public Task WarnAsync(string source, string operation, string message, string? detailsJson = null, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = OperationLogSeverity.Warning, Source = source, Operation = operation, Message = message, DetailsJson = detailsJson }, ct);

		public Task ErrorAsync(string source, string operation, string message, Exception? exception, OperationLogSeverity severity = OperationLogSeverity.Error, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = severity, Source = source, Operation = operation, Message = message, Exception = exception }, ct);

		public Task DebugAsync(string source, string operation, string message, Func<string?>? detailsBuilder = null, string? correlationId = null, CancellationToken ct = default)
			=> Task.CompletedTask;
	}
}
